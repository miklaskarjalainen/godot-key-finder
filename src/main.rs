use std::ops::Range;
use std::sync::Arc;
use std::sync::RwLock;
use std::thread;

mod pck;

const THREAD_COUNT: usize = 1;

fn brute_force(
    ctx_arc: Arc<RwLock<pck::DecryptContext>>,
    binary_arc: Arc<RwLock<Vec<u8>>>,
    check_range: Range<usize>,
) {
    // Going through the indexes in reverse, it seems like the encryption key is at the end of the binary.
    let bin = binary_arc.read().expect("?");
    let ctx = ctx_arc.read().expect("?");

    let mut buffer = ctx.create_buffer();

    let range_len = check_range.len();
    for (idx, offset) in check_range.rev().enumerate() {
        let possible_key = &bin[offset..(offset + 32)];

        if ctx.try_decrypt(possible_key, &mut buffer) {
            println!(
                "KEY FOUND in {} ({:.2}%) iterations!\n The key is {:X?}",
                idx,
                (idx as f32) / (range_len as f32) * 100.0f32,
                hex::encode(possible_key)
            );
            break;
        }

        if idx % 10_000 == 0 {
            println!(
                "CHECKED {} COMBINATIONS! ({:.2}% of the binary checked)",
                idx,
                (idx as f32) / (range_len as f32) * 100.0f32
            );
        }
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 3 {
        println!("usage: <pck-filepath> <binary-filepath>");
        println!("usage: <binary-filepath> --embedded");
        return;
    }

    let embedded = args[2] == "--embedded";
    let (pck_file, pck_begin) = if embedded {
        pck::PckFile::new_embedded(&args[1])
    } else {
        (pck::PckFile::new(&args[1]), 0usize)
    };

    let decrypt_details = Arc::new(RwLock::new(pck::DecryptContext::from(pck_file)));

    let binary_arc = Arc::new(RwLock::new(
        if embedded {
            std::fs::read(&args[1])
        } else {
            std::fs::read(&args[2])
        }
        .expect("binary not found!"),
    ));

    let real_size = if embedded {
        pck_begin
    } else {
        binary_arc.read().unwrap().len()
    };
    // Bit of a hack to make sure that we don't go out of bounds, this way no if statement is needed in the for loop.
    binary_arc.write().unwrap().resize(real_size + 32, 0u8);

    // Balance the work for all the threads.
    let mut thread_handles = vec![];

    let chunk_size = real_size / THREAD_COUNT;
    for i in 0..THREAD_COUNT {
        let range_begin = i * chunk_size;
        let range_end = range_begin + chunk_size;
        let range = range_begin..range_end;

        let ctx = decrypt_details.clone();
        let binary = binary_arc.clone();
        thread_handles.push(thread::spawn(move || {
            println!("THREAD {:?} spawned!", thread::current().id());
            brute_force(ctx, binary, range);
        }));
    }

    for j in thread_handles {
        j.join().expect("?");
    }
}
