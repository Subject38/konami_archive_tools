use clap::Parser;
use k_archives::mount;
use std::{io::BufWriter, path::PathBuf};

#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Filename of konami archive. Supports (mar, bar, qar, d2, cab, lst, and info)
    filenames: Vec<PathBuf>,
    /// Parent folder to output to. If none, the the output will default to filename+"-extract"
    #[clap(short, long)]
    output_folder: Option<PathBuf>,
}

fn main() {
    let args: Args = Args::parse();
    for filename in args.filenames {
        let output = match args.output_folder {
            Some(ref output) => {
                let mut new = PathBuf::new();
                new.push(output);
                new.push(filename.file_stem().unwrap());
                new
            }
            None => format!("{}-extract", &filename.display()).into(),
        };
        let archive = mount(filename).expect("Failed to parse konami update archive");
        for filepath in archive.list_files() {
            let mut file = archive.open(&filepath).expect("File should exist...");
            let mut output_file_path = output.clone();
            output_file_path.push(&file.name);
            std::fs::create_dir_all(output_file_path.parent().unwrap()).unwrap();
            let mut file_buffer = BufWriter::new(std::fs::File::create(&output_file_path).unwrap());
            println!("{}", output_file_path.display());
            std::io::copy(&mut file, &mut file_buffer).unwrap();
        }
    }
}
