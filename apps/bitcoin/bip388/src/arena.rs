//! Arena / index-based storage for BIP-388 descriptor templates.
//!
//! The descriptor AST is stored in a small set of flat, pointer-free pools and
//! addressed by `u32` ids. This lets the *same* parser, classifier and renderer
//! run against two backings:
//!
//! * [`VecArena`] — growable `Vec`-backed pools, used by the default `alloc`
//!   build (behaves like the historical `Box`/`Vec` AST, but flat).
//! * a future `SliceArena` — bump cursors over a caller-provided `&mut [u8]`,
//!   used by the no-alloc / C build (no global allocator, no `Vec`/`Box`).
//!
//! All node records are fixed-size and `Copy`, and all cross-references are
//! `u32` indices, so the layout is portable and there is no recursion through
//! owned pointers.
//!
//! Computation is written once against borrowed [`Cursor`]s (see [`Cursor::view`]
//! / [`DescriptorNode`]), so it is backing-agnostic.
//!
//! NOTE: this module is wired into the rest of the crate incrementally across
//! the migration phases; until then several items are intentionally unused.
#![allow(dead_code, unused_imports)]

use core::fmt;

/// Sentinel for "no node" / "no link" in a `u32` reference.
pub const NONE: u32 = u32::MAX;

/// Maximum tap-tree / traversal depth (mirrors `MAX_PARSE_DEPTH` in `lib.rs`).
pub const MAX_TREE_DEPTH: usize = 64;

/// Index into the arena's `nodes` pool (descriptor *and* tap-tree nodes).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct NodeId(pub u32);

/// Index into the arena's `keys` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash)]
pub struct KeyId(pub u32);

/// A contiguous `[start, start+len)` span into a typed pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Span {
    pub start: u32,
    pub len: u32,
}

impl Span {
    pub const EMPTY: Span = Span { start: 0, len: 0 };
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

/// Discriminant for a [`Node`]. `repr(u8)` keeps the record compact and stable.
///
/// Covers every `DescriptorTemplate` variant plus the two tap-tree node kinds
/// (`TapLeaf` / `TapBranch`), which share the `nodes` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum NodeTag {
    // top-level / script-context wrappers around a single child (a = child NodeId)
    Sh,
    Wsh,
    // single-letter miniscript wrappers (a = child NodeId)
    A,
    S,
    C,
    T,
    D,
    V,
    J,
    N,
    L,
    U,
    // key fragments (a = KeyId)
    Pkh,
    Wpkh,
    Pk,
    PkK,
    PkH,
    // taproot top level (a = KeyId, d = tap-tree root NodeId | NONE)
    Tr,
    // constants
    Zero,
    One,
    // numeric locktimes (a = value)
    Older,
    After,
    // hash fragments ((a,b) = bytes Span; len 32)
    Sha256,
    Hash256,
    // hash fragments ((a,b) = bytes Span; len 20)
    Ripemd160,
    Hash160,
    // combinators (a,b,c = child NodeIds)
    Andor,
    AndV,
    AndB,
    AndN,
    OrB,
    OrC,
    OrD,
    OrI,
    // threshold over sub-scripts (a = k, b = head link, c = child count)
    Thresh,
    // multisig over keys (a = k, b = head link, c = key count)
    Multi,
    MultiA,
    Sortedmulti,
    SortedmultiA,
    // tap-tree nodes
    TapLeaf,   // a = script NodeId
    TapBranch, // a = left NodeId, b = right NodeId
}

/// A fixed-size, `Copy` descriptor or tap-tree node. Fields `a..d` are
/// interpreted per [`NodeTag`] (see the tag docs above).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Node {
    pub tag: NodeTag,
    pub a: u32,
    pub b: u32,
    pub c: u32,
    pub d: u32,
}

impl Node {
    pub fn new(tag: NodeTag) -> Node {
        Node {
            tag,
            a: 0,
            b: 0,
            c: 0,
            d: 0,
        }
    }
    pub fn with_a(tag: NodeTag, a: u32) -> Node {
        Node { tag, a, b: 0, c: 0, d: 0 }
    }
}

/// Plain vs. musig key expression.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum KeyKind {
    Plain = 0,
    Musig = 1,
}

/// A `Copy`, pointer-free key expression. For a plain key, `plain_index` is the
/// key-information index and `musig_members` is empty; for a musig key,
/// `musig_members` is a span of member indices in the `members` pool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct KeyExprRec {
    pub num1: u32,
    pub num2: u32,
    pub kind: KeyKind,
    pub plain_index: u32,
    pub musig_members: Span,
}

impl KeyExprRec {
    pub fn plain(plain_index: u32, num1: u32, num2: u32) -> KeyExprRec {
        KeyExprRec {
            num1,
            num2,
            kind: KeyKind::Plain,
            plain_index,
            musig_members: Span::EMPTY,
        }
    }
    pub fn musig(musig_members: Span, num1: u32, num2: u32) -> KeyExprRec {
        KeyExprRec {
            num1,
            num2,
            kind: KeyKind::Musig,
            plain_index: 0,
            musig_members,
        }
    }
}

/// A cons cell for the singly-linked lists used by `Thresh` (NodeIds) and
/// `Multi*` (KeyIds). Cons cells make list building robust against the
/// allocation interleaving that happens while parsing nested sub-fragments
/// (e.g. a musig key inside a `multi_a`, or a `thresh` inside a `thresh`).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link {
    pub val: u32,
    pub next: u32,
}

/// Returned by allocation methods when a fixed-capacity backing is exhausted
/// (or when a `u32` id space would overflow).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct ArenaFull;

// ---------------------------------------------------------------------------
// Read / build abstractions
// ---------------------------------------------------------------------------

/// Read-only view of an arena. [`Cursor`]s are generic over this so traversal
/// code is written once for every backing.
pub trait ArenaRead {
    fn node(&self, id: NodeId) -> Node;
    fn key(&self, id: KeyId) -> KeyExprRec;
    fn link(&self, idx: u32) -> Link;
    fn members(&self, span: Span) -> &[u32];
    fn bytes(&self, span: Span) -> &[u8];
}

/// Append-only builder API shared by all backings, so the parser is generic
/// over it. Every method is fallible: `VecArena` only fails on `u32` overflow,
/// while a fixed-capacity backing fails when exhausted.
pub trait ArenaStore: ArenaRead {
    fn push_node(&mut self, node: Node) -> Result<NodeId, ArenaFull>;
    fn push_key(&mut self, key: KeyExprRec) -> Result<KeyId, ArenaFull>;
    fn push_link(&mut self, link: Link) -> Result<u32, ArenaFull>;
    /// Patch the `next` field of a previously pushed link (for in-order lists).
    fn set_link_next(&mut self, idx: u32, next: u32);

    /// Begin a contiguous span in the `members` pool. Returns the start index.
    fn members_begin(&self) -> u32;
    /// Append one value to the `members` pool (must not interleave with other
    /// `members` pushes — see the musig parsing path).
    fn members_push(&mut self, value: u32) -> Result<(), ArenaFull>;
    /// Finish a span started at `start` (the current `members` length is the end).
    fn members_end(&self, start: u32) -> Span;

    /// Append a byte run (hash fragment) and return its span.
    fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull>;

    /// Mutate a stored key's derivation indices in place (used by the decode
    /// path's canonicalization, addressed by id with no aliasing).
    fn set_key_derivation(&mut self, id: KeyId, num1: u32, num2: u32);
}

/// In-order cons-list builder. Holds the head and tail link indices and the
/// element count, so finished lists keep parse order with `O(1)` appends.
#[derive(Clone, Copy, Debug)]
pub struct ListBuilder {
    head: u32,
    tail: u32,
    count: u32,
}

impl ListBuilder {
    pub fn new() -> ListBuilder {
        ListBuilder {
            head: NONE,
            tail: NONE,
            count: 0,
        }
    }

    /// Append `val` (a NodeId or KeyId) to the list.
    pub fn push<A: ArenaStore>(&mut self, store: &mut A, val: u32) -> Result<(), ArenaFull> {
        let idx = store.push_link(Link { val, next: NONE })?;
        if self.head == NONE {
            self.head = idx;
        } else {
            store.set_link_next(self.tail, idx);
        }
        self.tail = idx;
        self.count += 1;
        Ok(())
    }

    pub fn head(&self) -> u32 {
        self.head
    }
    pub fn count(&self) -> u32 {
        self.count
    }
}

impl Default for ListBuilder {
    fn default() -> Self {
        ListBuilder::new()
    }
}

// ---------------------------------------------------------------------------
// VecArena (alloc-backed)
// ---------------------------------------------------------------------------

// The default build currently always has `alloc`; the explicit `alloc` feature
// gate (and the no-alloc `SliceArena`) are introduced in later phases.
pub use vec_arena::VecArena;

mod vec_arena {
    use super::*;
    use alloc::vec::Vec;

    /// Growable, `Vec`-backed arena. Allocation only fails on `u32` overflow.
    #[derive(Clone, Debug, Default)]
    pub struct VecArena {
        nodes: Vec<Node>,
        keys: Vec<KeyExprRec>,
        links: Vec<Link>,
        members: Vec<u32>,
        bytes: Vec<u8>,
    }

    impl VecArena {
        pub fn new() -> VecArena {
            VecArena::default()
        }

        pub fn node_count(&self) -> usize {
            self.nodes.len()
        }
    }

    impl ArenaRead for VecArena {
        fn node(&self, id: NodeId) -> Node {
            self.nodes[id.0 as usize]
        }
        fn key(&self, id: KeyId) -> KeyExprRec {
            self.keys[id.0 as usize]
        }
        fn link(&self, idx: u32) -> Link {
            self.links[idx as usize]
        }
        fn members(&self, span: Span) -> &[u32] {
            &self.members[span.start as usize..(span.start + span.len) as usize]
        }
        fn bytes(&self, span: Span) -> &[u8] {
            &self.bytes[span.start as usize..(span.start + span.len) as usize]
        }
    }

    impl ArenaStore for VecArena {
        fn push_node(&mut self, node: Node) -> Result<NodeId, ArenaFull> {
            let id = u32::try_from(self.nodes.len()).map_err(|_| ArenaFull)?;
            self.nodes.push(node);
            Ok(NodeId(id))
        }
        fn push_key(&mut self, key: KeyExprRec) -> Result<KeyId, ArenaFull> {
            let id = u32::try_from(self.keys.len()).map_err(|_| ArenaFull)?;
            self.keys.push(key);
            Ok(KeyId(id))
        }
        fn push_link(&mut self, link: Link) -> Result<u32, ArenaFull> {
            let idx = u32::try_from(self.links.len()).map_err(|_| ArenaFull)?;
            self.links.push(link);
            Ok(idx)
        }
        fn set_link_next(&mut self, idx: u32, next: u32) {
            self.links[idx as usize].next = next;
        }
        fn members_begin(&self) -> u32 {
            self.members.len() as u32
        }
        fn members_push(&mut self, value: u32) -> Result<(), ArenaFull> {
            if self.members.len() >= u32::MAX as usize {
                return Err(ArenaFull);
            }
            self.members.push(value);
            Ok(())
        }
        fn members_end(&self, start: u32) -> Span {
            Span {
                start,
                len: self.members.len() as u32 - start,
            }
        }
        fn push_bytes(&mut self, bytes: &[u8]) -> Result<Span, ArenaFull> {
            let start = u32::try_from(self.bytes.len()).map_err(|_| ArenaFull)?;
            let len = u32::try_from(bytes.len()).map_err(|_| ArenaFull)?;
            self.bytes.extend_from_slice(bytes);
            Ok(Span { start, len })
        }
        fn set_key_derivation(&mut self, id: KeyId, num1: u32, num2: u32) {
            let k = &mut self.keys[id.0 as usize];
            k.num1 = num1;
            k.num2 = num2;
        }
    }
}

// ---------------------------------------------------------------------------
// Cursors / views (backing-agnostic traversal)
// ---------------------------------------------------------------------------

/// A borrowed reference to a descriptor node within an arena.
pub struct Cursor<'a, A: ArenaRead> {
    arena: &'a A,
    id: NodeId,
}

// Manual Clone/Copy so the cursor types stay `Copy` regardless of whether the
// backing arena `A` is `Copy` (it holds only a shared reference to `A`).
impl<'a, A: ArenaRead> Clone for Cursor<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for Cursor<'a, A> {}

impl<'a, A: ArenaRead> Cursor<'a, A> {
    pub fn new(arena: &'a A, id: NodeId) -> Self {
        Cursor { arena, id }
    }
    pub fn arena(&self) -> &'a A {
        self.arena
    }
    pub fn id(&self) -> NodeId {
        self.id
    }
    pub fn tag(&self) -> NodeTag {
        self.arena.node(self.id).tag
    }
    fn raw(&self) -> Node {
        self.arena.node(self.id)
    }
    fn child(&self, slot_field: u32) -> Cursor<'a, A> {
        Cursor::new(self.arena, NodeId(slot_field))
    }
    fn key_at(&self, id: u32) -> KeyView<'a, A> {
        KeyView {
            arena: self.arena,
            rec: self.arena.key(KeyId(id)),
        }
    }

    /// Resolve this node to a borrowed, matchable view.
    pub fn view(&self) -> DescriptorNode<'a, A> {
        let n = self.raw();
        use NodeTag::*;
        match n.tag {
            Sh => DescriptorNode::Sh(self.child(n.a)),
            Wsh => DescriptorNode::Wsh(self.child(n.a)),
            A => DescriptorNode::A(self.child(n.a)),
            S => DescriptorNode::S(self.child(n.a)),
            C => DescriptorNode::C(self.child(n.a)),
            T => DescriptorNode::T(self.child(n.a)),
            D => DescriptorNode::D(self.child(n.a)),
            V => DescriptorNode::V(self.child(n.a)),
            J => DescriptorNode::J(self.child(n.a)),
            N => DescriptorNode::N(self.child(n.a)),
            L => DescriptorNode::L(self.child(n.a)),
            U => DescriptorNode::U(self.child(n.a)),
            Pkh => DescriptorNode::Pkh(self.key_at(n.a)),
            Wpkh => DescriptorNode::Wpkh(self.key_at(n.a)),
            Pk => DescriptorNode::Pk(self.key_at(n.a)),
            PkK => DescriptorNode::PkK(self.key_at(n.a)),
            PkH => DescriptorNode::PkH(self.key_at(n.a)),
            Tr => {
                let tree = if n.d == NONE {
                    None
                } else {
                    Some(TapCursor::new(self.arena, NodeId(n.d)))
                };
                DescriptorNode::Tr(self.key_at(n.a), tree)
            }
            Zero => DescriptorNode::Zero,
            One => DescriptorNode::One,
            Older => DescriptorNode::Older(n.a),
            After => DescriptorNode::After(n.a),
            Sha256 => DescriptorNode::Sha256(self.arena.bytes(Span { start: n.a, len: n.b })),
            Hash256 => DescriptorNode::Hash256(self.arena.bytes(Span { start: n.a, len: n.b })),
            Ripemd160 => DescriptorNode::Ripemd160(self.arena.bytes(Span { start: n.a, len: n.b })),
            Hash160 => DescriptorNode::Hash160(self.arena.bytes(Span { start: n.a, len: n.b })),
            Andor => DescriptorNode::Andor(self.child(n.a), self.child(n.b), self.child(n.c)),
            AndV => DescriptorNode::AndV(self.child(n.a), self.child(n.b)),
            AndB => DescriptorNode::AndB(self.child(n.a), self.child(n.b)),
            AndN => DescriptorNode::AndN(self.child(n.a), self.child(n.b)),
            OrB => DescriptorNode::OrB(self.child(n.a), self.child(n.b)),
            OrC => DescriptorNode::OrC(self.child(n.a), self.child(n.b)),
            OrD => DescriptorNode::OrD(self.child(n.a), self.child(n.b)),
            OrI => DescriptorNode::OrI(self.child(n.a), self.child(n.b)),
            Thresh => DescriptorNode::Thresh(
                n.a,
                NodeList {
                    arena: self.arena,
                    cur: n.b,
                    count: n.c,
                },
            ),
            Multi => DescriptorNode::Multi(n.a, self.key_list(n.b, n.c)),
            MultiA => DescriptorNode::MultiA(n.a, self.key_list(n.b, n.c)),
            Sortedmulti => DescriptorNode::Sortedmulti(n.a, self.key_list(n.b, n.c)),
            SortedmultiA => DescriptorNode::SortedmultiA(n.a, self.key_list(n.b, n.c)),
            TapLeaf | TapBranch => DescriptorNode::TapNode(TapCursor::new(self.arena, self.id)),
        }
    }

    fn key_list(&self, head: u32, count: u32) -> KeyListView<'a, A> {
        KeyListView {
            arena: self.arena,
            head,
            count,
        }
    }
}

/// Construct a [`KeyView`] for a key id (used when materializing an owned
/// `KeyExpression` from a parsed `KeyId`).
pub fn key_view<A: ArenaRead>(arena: &A, id: KeyId) -> KeyView<'_, A> {
    KeyView {
        arena,
        rec: arena.key(id),
    }
}

/// A borrowed key expression.
pub struct KeyView<'a, A: ArenaRead> {
    arena: &'a A,
    rec: KeyExprRec,
}
impl<'a, A: ArenaRead> Clone for KeyView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for KeyView<'a, A> {}

impl<'a, A: ArenaRead> KeyView<'a, A> {
    pub fn num1(&self) -> u32 {
        self.rec.num1
    }
    pub fn num2(&self) -> u32 {
        self.rec.num2
    }
    pub fn is_plain(&self) -> bool {
        self.rec.kind == KeyKind::Plain
    }
    pub fn is_musig(&self) -> bool {
        self.rec.kind == KeyKind::Musig
    }
    pub fn plain_key_index(&self) -> Option<u32> {
        match self.rec.kind {
            KeyKind::Plain => Some(self.rec.plain_index),
            KeyKind::Musig => None,
        }
    }
    pub fn musig_key_indices(&self) -> Option<&'a [u32]> {
        match self.rec.kind {
            KeyKind::Musig => Some(self.arena.members(self.rec.musig_members)),
            KeyKind::Plain => None,
        }
    }
}

/// A borrowed list of key expressions (for `multi`/`sortedmulti`/`_a`).
pub struct KeyListView<'a, A: ArenaRead> {
    arena: &'a A,
    head: u32,
    count: u32,
}
impl<'a, A: ArenaRead> Clone for KeyListView<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for KeyListView<'a, A> {}

impl<'a, A: ArenaRead> KeyListView<'a, A> {
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn iter(&self) -> KeyListIter<'a, A> {
        KeyListIter {
            arena: self.arena,
            cur: self.head,
        }
    }
}

pub struct KeyListIter<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
}

impl<'a, A: ArenaRead> Iterator for KeyListIter<'a, A> {
    type Item = KeyView<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == NONE {
            return None;
        }
        let link = self.arena.link(self.cur);
        self.cur = link.next;
        Some(KeyView {
            arena: self.arena,
            rec: self.arena.key(KeyId(link.val)),
        })
    }
}

/// A borrowed list of sub-script nodes (for `thresh`).
pub struct NodeList<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
    count: u32,
}
impl<'a, A: ArenaRead> Clone for NodeList<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for NodeList<'a, A> {}

impl<'a, A: ArenaRead> NodeList<'a, A> {
    pub fn len(&self) -> usize {
        self.count as usize
    }
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }
    pub fn iter(&self) -> NodeListIter<'a, A> {
        NodeListIter {
            arena: self.arena,
            cur: self.cur,
        }
    }
}

pub struct NodeListIter<'a, A: ArenaRead> {
    arena: &'a A,
    cur: u32,
}

impl<'a, A: ArenaRead> Iterator for NodeListIter<'a, A> {
    type Item = Cursor<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.cur == NONE {
            return None;
        }
        let link = self.arena.link(self.cur);
        self.cur = link.next;
        Some(Cursor::new(self.arena, NodeId(link.val)))
    }
}

/// A borrowed reference to a tap-tree node.
pub struct TapCursor<'a, A: ArenaRead> {
    arena: &'a A,
    id: NodeId,
}
impl<'a, A: ArenaRead> Clone for TapCursor<'a, A> {
    fn clone(&self) -> Self {
        *self
    }
}
impl<'a, A: ArenaRead> Copy for TapCursor<'a, A> {}

impl<'a, A: ArenaRead> TapCursor<'a, A> {
    pub fn new(arena: &'a A, id: NodeId) -> Self {
        TapCursor { arena, id }
    }
    pub fn is_leaf(&self) -> bool {
        self.arena.node(self.id).tag == NodeTag::TapLeaf
    }
    /// For a `TapLeaf`, the leaf script cursor.
    pub fn leaf_script(&self) -> Option<Cursor<'a, A>> {
        let n = self.arena.node(self.id);
        if n.tag == NodeTag::TapLeaf {
            Some(Cursor::new(self.arena, NodeId(n.a)))
        } else {
            None
        }
    }
    /// For a `TapBranch`, the (left, right) child tap-cursors.
    pub fn branch(&self) -> Option<(TapCursor<'a, A>, TapCursor<'a, A>)> {
        let n = self.arena.node(self.id);
        if n.tag == NodeTag::TapBranch {
            Some((
                TapCursor::new(self.arena, NodeId(n.a)),
                TapCursor::new(self.arena, NodeId(n.b)),
            ))
        } else {
            None
        }
    }
    /// Iterate the leaf script cursors left-to-right (matching the historical
    /// `TapleavesIter`), using a fixed-capacity stack (no allocation).
    pub fn tapleaves(&self) -> TapleavesIter<'a, A> {
        let mut stack = [NodeId(0); MAX_TREE_DEPTH + 1];
        stack[0] = self.id;
        TapleavesIter {
            arena: self.arena,
            stack,
            depth: 1,
        }
    }
}

pub struct TapleavesIter<'a, A: ArenaRead> {
    arena: &'a A,
    stack: [NodeId; MAX_TREE_DEPTH + 1],
    depth: usize,
}

impl<'a, A: ArenaRead> Iterator for TapleavesIter<'a, A> {
    type Item = Cursor<'a, A>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.depth > 0 {
            self.depth -= 1;
            let id = self.stack[self.depth];
            let n = self.arena.node(id);
            match n.tag {
                NodeTag::TapLeaf => return Some(Cursor::new(self.arena, NodeId(n.a))),
                NodeTag::TapBranch => {
                    // push right then left so left is popped first
                    if self.depth + 2 <= self.stack.len() {
                        self.stack[self.depth] = NodeId(n.b);
                        self.stack[self.depth + 1] = NodeId(n.a);
                        self.depth += 2;
                    }
                }
                _ => {}
            }
        }
        None
    }
}

/// A borrowed, matchable view of a descriptor node. Produced by [`Cursor::view`].
pub enum DescriptorNode<'a, A: ArenaRead> {
    Sh(Cursor<'a, A>),
    Wsh(Cursor<'a, A>),
    A(Cursor<'a, A>),
    S(Cursor<'a, A>),
    C(Cursor<'a, A>),
    T(Cursor<'a, A>),
    D(Cursor<'a, A>),
    V(Cursor<'a, A>),
    J(Cursor<'a, A>),
    N(Cursor<'a, A>),
    L(Cursor<'a, A>),
    U(Cursor<'a, A>),
    Pkh(KeyView<'a, A>),
    Wpkh(KeyView<'a, A>),
    Pk(KeyView<'a, A>),
    PkK(KeyView<'a, A>),
    PkH(KeyView<'a, A>),
    Tr(KeyView<'a, A>, Option<TapCursor<'a, A>>),
    Zero,
    One,
    Older(u32),
    After(u32),
    Sha256(&'a [u8]),
    Hash256(&'a [u8]),
    Ripemd160(&'a [u8]),
    Hash160(&'a [u8]),
    Andor(Cursor<'a, A>, Cursor<'a, A>, Cursor<'a, A>),
    AndV(Cursor<'a, A>, Cursor<'a, A>),
    AndB(Cursor<'a, A>, Cursor<'a, A>),
    AndN(Cursor<'a, A>, Cursor<'a, A>),
    OrB(Cursor<'a, A>, Cursor<'a, A>),
    OrC(Cursor<'a, A>, Cursor<'a, A>),
    OrD(Cursor<'a, A>, Cursor<'a, A>),
    OrI(Cursor<'a, A>, Cursor<'a, A>),
    Thresh(u32, NodeList<'a, A>),
    Multi(u32, KeyListView<'a, A>),
    MultiA(u32, KeyListView<'a, A>),
    Sortedmulti(u32, KeyListView<'a, A>),
    SortedmultiA(u32, KeyListView<'a, A>),
    /// A tap-tree node encountered directly (only when a `Cursor` is aimed at a
    /// `TapLeaf`/`TapBranch`); normal traversal reaches leaves via [`TapCursor`].
    TapNode(TapCursor<'a, A>),
}

// ---------------------------------------------------------------------------
// Cleartext output sink
// ---------------------------------------------------------------------------

/// A sink for cleartext output: a `core::fmt::Write` plus a line separator.
/// The encoder writes one logical description per "line" and calls
/// [`LineSink::flush_line`] between them.
pub trait LineSink: fmt::Write {
    /// Finish the current line and start a new one.
    fn flush_line(&mut self);
}

pub use vec_sink::VecLineSink;

mod vec_sink {
    use super::*;
    use alloc::string::String;
    use alloc::vec::Vec;

    /// Collects cleartext lines into `Vec<String>` (alloc build).
    #[derive(Default)]
    pub struct VecLineSink {
        lines: Vec<String>,
        cur: String,
    }

    impl VecLineSink {
        pub fn new() -> VecLineSink {
            VecLineSink::default()
        }
        /// Consume the sink, flushing any pending current line, into the lines.
        pub fn into_lines(mut self) -> Vec<String> {
            if !self.cur.is_empty() {
                self.lines.push(core::mem::take(&mut self.cur));
            }
            self.lines
        }
    }

    impl fmt::Write for VecLineSink {
        fn write_str(&mut self, s: &str) -> fmt::Result {
            self.cur.push_str(s);
            Ok(())
        }
    }

    impl LineSink for VecLineSink {
        fn flush_line(&mut self) {
            self.lines.push(core::mem::take(&mut self.cur));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;

    // Build `pkh(@0/**)` and read it back through a cursor.
    #[test]
    fn build_and_read_pkh() {
        let mut a = VecArena::new();
        let k = a.push_key(KeyExprRec::plain(0, 0, 1)).unwrap();
        let root = a.push_node(Node::with_a(NodeTag::Pkh, k.0)).unwrap();

        let cur = Cursor::new(&a, root);
        match cur.view() {
            DescriptorNode::Pkh(kv) => {
                assert!(kv.is_plain());
                assert_eq!(kv.plain_key_index(), Some(0));
                assert_eq!((kv.num1(), kv.num2()), (0, 1));
                assert_eq!(kv.musig_key_indices(), None);
            }
            _ => panic!("expected Pkh"),
        }
    }

    // Build `multi(2,@0,@1,@2)` via an in-order cons list.
    #[test]
    fn build_and_read_multi() {
        let mut a = VecArena::new();
        let mut list = ListBuilder::new();
        for i in 0..3u32 {
            let k = a.push_key(KeyExprRec::plain(i, 0, 1)).unwrap();
            list.push(&mut a, k.0).unwrap();
        }
        let mut node = Node::new(NodeTag::Multi);
        node.a = 2; // threshold
        node.b = list.head();
        node.c = list.count();
        let root = a.push_node(node).unwrap();

        match Cursor::new(&a, root).view() {
            DescriptorNode::Multi(k, keys) => {
                assert_eq!(k, 2);
                assert_eq!(keys.len(), 3);
                let indices: alloc::vec::Vec<u32> =
                    keys.iter().map(|kv| kv.plain_key_index().unwrap()).collect();
                assert_eq!(indices, alloc::vec![0, 1, 2]);
            }
            _ => panic!("expected Multi"),
        }
    }

    // Build `musig(@3,@7)` and read its members as a contiguous slice.
    #[test]
    fn build_and_read_musig() {
        let mut a = VecArena::new();
        let start = a.members_begin();
        a.members_push(3).unwrap();
        a.members_push(7).unwrap();
        let span = a.members_end(start);
        let k = a.push_key(KeyExprRec::musig(span, 0, 1)).unwrap();
        let root = a.push_node(Node::with_a(NodeTag::Pk, k.0)).unwrap();

        match Cursor::new(&a, root).view() {
            DescriptorNode::Pk(kv) => {
                assert!(kv.is_musig());
                assert_eq!(kv.musig_key_indices(), Some(&[3u32, 7u32][..]));
                assert_eq!(kv.plain_key_index(), None);
            }
            _ => panic!("expected Pk(musig)"),
        }
    }

    // Build a tap tree `{leaf(@0), {leaf(@1), leaf(@2)}}` and check left-to-right leaf order.
    #[test]
    fn build_and_iterate_tapleaves() {
        let mut a = VecArena::new();
        let mk_leaf = |a: &mut VecArena, idx: u32| {
            let k = a.push_key(KeyExprRec::plain(idx, 0, 1)).unwrap();
            let script = a.push_node(Node::with_a(NodeTag::Pk, k.0)).unwrap();
            a.push_node(Node::with_a(NodeTag::TapLeaf, script.0)).unwrap()
        };
        let l0 = mk_leaf(&mut a, 0);
        let l1 = mk_leaf(&mut a, 1);
        let l2 = mk_leaf(&mut a, 2);
        let mut inner = Node::new(NodeTag::TapBranch);
        inner.a = l1.0;
        inner.b = l2.0;
        let inner = a.push_node(inner).unwrap();
        let mut root = Node::new(NodeTag::TapBranch);
        root.a = l0.0;
        root.b = inner.0;
        let root = a.push_node(root).unwrap();

        let tc = TapCursor::new(&a, root);
        let order: alloc::vec::Vec<u32> = tc
            .tapleaves()
            .map(|leaf| match leaf.view() {
                DescriptorNode::Pk(kv) => kv.plain_key_index().unwrap(),
                _ => panic!("expected Pk leaf"),
            })
            .collect();
        assert_eq!(order, alloc::vec![0, 1, 2]);
    }

    #[test]
    fn line_sink_collects_lines() {
        let mut sink = VecLineSink::new();
        write!(sink, "first {}", 1).unwrap();
        sink.flush_line();
        write!(sink, "second").unwrap();
        let lines = sink.into_lines();
        assert_eq!(lines, alloc::vec!["first 1".to_string(), "second".to_string()]);
    }
}
