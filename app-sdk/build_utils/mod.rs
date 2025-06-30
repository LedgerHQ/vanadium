use common::ux::*;
use std::{fs::File, io::Write};

pub fn gen_u8_slice(data: &[u8]) -> String {
    format!(
        "[{}]",
        data.iter()
            .map(|b| format!("{}u8", b))
            .collect::<Vec<String>>()
            .join(", ")
    )
}

fn merge_static_parts(parts: &[SerializedPart]) -> Vec<SerializedPart> {
    let mut result = Vec::new();

    for part in parts {
        match part {
            SerializedPart::Static(vec) => {
                if let Some(SerializedPart::Static(last_vec)) = result.last_mut() {
                    // If the last element is Static, extend its vector
                    last_vec.extend(vec);
                } else {
                    // Otherwise, add a new Static element
                    result.push(SerializedPart::Static(vec.clone()));
                }
            }
            SerializedPart::Runtime { arg_name, arg_type } => {
                // Add Runtime elements as is
                result.push(SerializedPart::Runtime { arg_name, arg_type });
            }
        }
    }

    result
}

pub fn make_page_maker(file: &mut File, parts: &[SerializedPart], fn_name: &str) {
    let parts = merge_static_parts(parts);
    // make a list of all the Runtime parts
    let mut runtime_parts = Vec::new();
    for part in parts.iter() {
        if let SerializedPart::Runtime { arg_name, arg_type } = part {
            runtime_parts.push((arg_name, arg_type));
        }
    }

    let fn_args = runtime_parts
        .iter()
        .map(|(arg_name, arg_type)| format!("{}: {}", arg_name, arg_type))
        .collect::<Vec<String>>()
        .join(", ");

    writeln!(file, "#[allow(dead_code)]").expect("Could not write");
    writeln!(file, "#[inline(always)]").expect("Could not write");
    writeln!(file, "pub fn show_{}({}) {{", fn_name, fn_args).expect("Could not write");
    if parts.len() == 1 {
        // special case, can be optimized slightly
        match &parts[0] {
            SerializedPart::Static(vec) => {
                writeln!(
                    file,
                    "    let serialized: [u8; {}] = {};",
                    vec.len(),
                    gen_u8_slice(&vec)
                )
                .expect("Could not write");
            }
            SerializedPart::Runtime {
                arg_name,
                arg_type: _,
            } => {
                writeln!(
                    file,
                    "    let total_len: usize = {}.get_serialized_length();
    let mut serialized = Vec::<u8>::with_capacity(total_len);
    let mut cur: usize = 0;
    {}.serialize(&mut serialized, &mut cur);
    unsafe {{
        serialized.set_len(total_len);
    }}",
                    arg_name, arg_name
                )
                .expect("Could not write");
            }
        }

        writeln!(file, "    show_page_raw(&serialized);").expect("Could not write");
    } else {
        writeln!(file, "    let mut total_len: usize = 0;").expect("Could not write");

        // Compute total length
        for part in parts.iter() {
            match part {
                SerializedPart::Static(vec) => {
                    writeln!(file, "    total_len += {};", vec.len()).expect("Could not write");
                }
                SerializedPart::Runtime {
                    arg_name,
                    arg_type: _,
                } => {
                    writeln!(
                        file,
                        "    total_len += {}.get_serialized_length();",
                        arg_name
                    )
                    .expect("Could not write");
                }
            }
        }

        writeln!(file, "    const MAX_STATIC_LEN: usize = 64;").expect("Could not write");

        writeln!(file, "    if total_len <= MAX_STATIC_LEN {{").expect("Could not write");

        // if the total length is short enough, serialize each part, using a slice
        // this avoids allocations
        // We also use an uninitialized buffer, as we will overwrite it anyway

        writeln!(
            file,
            "        let mut buffer: MaybeUninit<[u8; MAX_STATIC_LEN]> = MaybeUninit::uninit();
        let buffer_ptr = buffer.as_mut_ptr() as *mut u8;
        let mut serialized = unsafe {{ core::slice::from_raw_parts_mut(buffer_ptr, MAX_STATIC_LEN) }};
        let mut cur: usize = 0;"
        )
        .expect("Could not write");

        for part in parts.iter() {
            match part {
                SerializedPart::Static(vec) => {
                    writeln!(
                        file,
                        "
        let next_len = {};
        serialized[cur..cur + next_len].copy_from_slice(&{});
        cur += next_len;",
                        vec.len(),
                        gen_u8_slice(&vec)
                    )
                    .expect("Could not write");
                }
                SerializedPart::Runtime {
                    arg_name,
                    arg_type: _,
                } => {
                    writeln!(
                        file,
                        "
        {}.serialize(&mut serialized, &mut cur);\n",
                        arg_name
                    )
                    .expect("Could not write");
                }
            }
        }

        writeln!(file, "        show_page_raw(&serialized[0..total_len]);")
            .expect("Could not write");

        writeln!(file, "    }} else {{").expect("Could not write");

        // serialize each part, using a vector
        // We don't initialize the vector's conmtent, as we will overwrite it anyway
        writeln!(
            file,
            "        let mut serialized = Vec::<u8>::with_capacity(total_len);
        unsafe {{
            serialized.set_len(total_len);
        }}

        let mut cur: usize = 0;"
        )
        .expect("Could not write");

        for part in parts.iter() {
            match part {
                SerializedPart::Static(vec) => {
                    writeln!(
                        file,
                        "
        let next_len = {};
        serialized[cur..cur + next_len].copy_from_slice(&{});
        cur += next_len;",
                        vec.len(),
                        gen_u8_slice(&vec)
                    )
                    .expect("Could not write");
                }
                SerializedPart::Runtime {
                    arg_name,
                    arg_type: _,
                } => {
                    writeln!(
                        file,
                        "
        {}.serialize(&mut serialized, &mut cur);\n",
                        arg_name
                    )
                    .expect("Could not write");
                }
            }
        }

        writeln!(file, "        show_page_raw(&serialized);").expect("Could not write");
        writeln!(file, "    }}").expect("Could not write");
    }
    writeln!(file, "}}\n").expect("Could not write");

    // Make a make_<page_name> function that returns the serialized page as a Vec<u8>
    writeln!(file, "#[allow(dead_code)]").expect("Could not write");
    writeln!(file, "#[inline(always)]").expect("Could not write");
    writeln!(file, "pub fn make_{}({}) -> Vec<u8> {{", fn_name, fn_args).expect("Could not write");

    writeln!(file, "    let mut total_len: usize = 0;").expect("Could not write");

    // Compute total length
    for part in parts.iter() {
        match part {
            SerializedPart::Static(vec) => {
                writeln!(file, "    total_len += {};", vec.len()).expect("Could not write");
            }
            SerializedPart::Runtime {
                arg_name,
                arg_type: _,
            } => {
                writeln!(
                    file,
                    "    total_len += {}.get_serialized_length();",
                    arg_name
                )
                .expect("Could not write");
            }
        }
    }

    // serialize each part, using a vector
    // We don't initialize the vector's conmtent, as we will overwrite it anyway
    writeln!(
        file,
        "    let mut serialized = Vec::<u8>::with_capacity(total_len);
    unsafe {{
        serialized.set_len(total_len);
    }}

    let mut cur: usize = 0;"
    )
    .expect("Could not write");

    for part in parts.iter() {
        match part {
            SerializedPart::Static(vec) => {
                writeln!(
                    file,
                    "
    let next_len = {};
    serialized[cur..cur + next_len].copy_from_slice(&{});
    cur += next_len;",
                    vec.len(),
                    gen_u8_slice(&vec)
                )
                .expect("Could not write");
            }
            SerializedPart::Runtime {
                arg_name,
                arg_type: _,
            } => {
                writeln!(
                    file,
                    "
    {}.serialize(&mut serialized, &mut cur);\n",
                    arg_name
                )
                .expect("Could not write");
            }
        }
    }
    writeln!(file, "    serialized").expect("Could not write");
    writeln!(file, "}}\n").expect("Could not write");
}
