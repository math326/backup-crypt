mod backup;
mod crypto;
mod restore;

use std::env;

fn main() {

    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Uso:");
        println!("vault_rust backup <arquivo_ou_pasta_origem> <destino.enc>");
        println!("vault_rust restore <arquivo.enc> <pasta_destino>");
        return;
    }

    match args[1].as_str() {

        "backup" => {
            if args.len() != 4 {
                println!("Uso: vault_rust backup <arquivo_ou_pasta_origem> <destino.enc>");
                return;
            }

            backup::run(&args[2], &args[3]);
        }

        "restore" => {
            if args.len() != 4 {
                println!("Uso: vault_rust restore <arquivo.enc> <pasta_destino>");
                return;
            }

            restore::run(&args[2], &args[3]);
        }

        _ => {
            println!("Comando inválido.");
        }
    }
}
