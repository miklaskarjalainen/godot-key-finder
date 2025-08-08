mod pck;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("usage: <pck-filepath> <binary-filepath>");
        println!("usage: <binary-filepath> --embedded");
        return;
    }

    let embedded = args[2] == "--embedded";
    let file = if embedded {
        pck::PckFile::new_embedded(&args[1])
    } else {
        pck::PckFile::new(&args[1])
    };

    let mut decrypt_details = pck::DecryptContext::from(file);
    let mut binary = if embedded {
        std::fs::read(&args[1])
    } else {
        std::fs::read(&args[2])
    }
    .expect("binary not found!");

    // Bit of a hack to make sure that we don't go out of bounds, this way no if statement is needed in the for loop.
    let old_size = binary.len();
    binary.resize(old_size + 32, 0u8);

    // Going through the indexes in reverse, it seems like the encryption key is at the end of the binary.
    for (idx, offset) in (0..old_size).rev().enumerate() {
        let possible_key = &binary[offset..(offset + 32)];

        if decrypt_details.try_decrypt(possible_key) {
            println!(
                "KEY FOUND in {} ({:.2}%) iterations!\n The key is {:X?}",
                idx,
                (idx as f32) / (binary.len() as f32) * 100.0f32,
                hex::encode(possible_key)
            );
            break;
        }

        if idx % 10_000 == 0 {
            println!(
                "CHECKED {} COMBINATIONS! ({:.2}% of the binary checked)",
                idx,
                (idx as f32) / (binary.len() as f32) * 100.0f32
            );
        }
    }
}
