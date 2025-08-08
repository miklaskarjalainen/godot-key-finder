mod args;
mod pck;

use args::Args;
use clap::Parser;
use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::{Duration, Instant};

const UPDATE_INTERVAL: Duration = Duration::from_millis(500);

struct WorkContext {
    ctx: pck::DecryptContext,
    binary_data: Vec<u8>,
    binary_size: usize, // binary_data gets extra data appended to prevent going out-of-bounds.

    iterations: AtomicU64,
    done: AtomicBool,
}

impl WorkContext {
    pub fn new(pck_path: &str, binary_path: &str, embedded: bool) -> Arc<RwLock<Self>> {
        let mut binary_data = std::fs::read(binary_path).expect("binary path is invalid!");
        let binary_size: usize;

        let pck_file = if embedded {
            let (f, s) = pck::PckFile::new_embedded(pck_path);
            binary_size = s;
            f
        } else {
            binary_size = binary_data.len();
            pck::PckFile::new(pck_path)
        };

        // Bit of a hack to make sure that we don't go out of bounds, this way no if statement is needed in the for loop.
        binary_data.resize(binary_size + 32, 0u8);

        let ctx = pck::DecryptContext::from(pck_file);

        Arc::new(RwLock::new(Self {
            ctx,
            binary_data,
            binary_size,

            iterations: AtomicU64::new(0),
            done: AtomicBool::new(false),
        }))
    }

    fn start_bruteforcing(rc: Arc<RwLock<Self>>, range: Range<usize>) {
        const UPDATE_ITER_RATE: u64 = 10_000;

        println!(
            "THREAD {:?} spawned! Searching range {:?}",
            thread::current().id(),
            range
        );

        let mut buffer = rc.read().unwrap().ctx.create_buffer();
        let mut thread_iter = 1u64;

        // Going through the indexes in reverse, it seems like the encryption key is at the end of the binary.
        for offset in range.rev() {
            // Take the next 32 bytes, try to use them as the key.
            let (result, key) = {
                let work = rc.read().unwrap();
                let possible_key = work.binary_data[offset..(offset + 32)]
                    .iter()
                    .copied()
                    .collect::<Vec<u8>>();
                (
                    work.ctx.try_decrypt(&possible_key, &mut buffer),
                    possible_key,
                )
            };

            if result {
                println!("KEY FOUND: '{}'", hex::encode(key));
                rc.write().unwrap().done.store(true, Ordering::Relaxed);
                return;
            }

            thread_iter += 1;
            if thread_iter >= UPDATE_ITER_RATE {
                let work = rc.write().unwrap();
                work.iterations.fetch_add(thread_iter, Ordering::Relaxed);
                thread_iter -= UPDATE_ITER_RATE;
                if work.done.load(Ordering::Relaxed) {
                    return;
                }
            }
        }
    }

    pub fn spawn_threads(
        ctx: Arc<RwLock<Self>>,
        thread_count: usize,
    ) -> Vec<thread::JoinHandle<()>> {
        assert!(thread_count > 0, "cannot be zero");

        let mut thread_handles = vec![];
        let chunk_size = ctx.read().unwrap().binary_size / thread_count;

        for i in 0..thread_count {
            let range_begin = i * chunk_size;
            let range_end = range_begin + chunk_size;
            let range = range_begin..range_end;

            let ctx = ctx.clone();
            thread_handles.push(thread::spawn(move || {
                Self::start_bruteforcing(ctx, range);
            }));
        }

        thread_handles
    }
}

fn main() {
    let args = Args::parse();
    assert_ne!(args.jobs, 0, "--jobs has to be greater than '0'!");

    let work_arc = match args.cmd {
        args::CommandType::Pck(cmd) => WorkContext::new(&cmd.pck, &cmd.bin, false),
        args::CommandType::Embedded(cmd) => WorkContext::new(&cmd.bin, &cmd.bin, true),
    };

    let threads = WorkContext::spawn_threads(work_arc.clone(), args.jobs.into());

    let binary_size = work_arc.read().unwrap().binary_size as f32;

    let begin = Instant::now();
    loop {
        thread::sleep(UPDATE_INTERVAL);

        let work = work_arc.read().unwrap();
        if work.done.load(Ordering::Relaxed) {
            break;
        }

        let iterations = work.iterations.load(Ordering::Relaxed);
        println!(
            "Searched {} iterations which is {:.2}% of the binary!",
            iterations,
            (iterations as f32) / binary_size * 100.0f32
        )
    }

    for j in threads {
        j.join().expect("?");
    }

    println!("Program was run for: {:?}", Instant::now() - begin);
}
