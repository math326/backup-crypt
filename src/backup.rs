use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use rpassword::prompt_password;
use tar::Builder;
use walkdir::WalkDir;

use crate::crypto::EncryptWriter;

pub fn run(origem: &str, destino: &str) {

    println!("Senha para criptografia:");
    let senha = match prompt_password("> ") {
        Ok(senha) => senha,
        Err(err) => {
            eprintln!("Erro ao ler senha: {err}");
            return;
        }
    };

    let origem_path = Path::new(origem);
    if !origem_path.exists() {
        eprintln!("Origem '{origem}' não existe.");
        return;
    }

    let origem_abs = match fs::canonicalize(origem_path) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Erro ao resolver caminho da origem '{origem}': {err}");
            return;
        }
    };

    let destino_abs = match resolve_destino_abs(Path::new(destino)) {
        Ok(path) => path,
        Err(err) => {
            eprintln!("Erro ao resolver caminho do destino '{destino}': {err}");
            return;
        }
    };

    if origem_abs.is_dir() && destino_abs.starts_with(&origem_abs) {
        eprintln!(
            "Destino inválido: '{destino}' está dentro da origem '{origem}'. Use um destino fora da pasta de origem para evitar recursão infinita."
        );
        return;
    }

    if origem_abs.is_file() && destino_abs == origem_abs {
        eprintln!("Destino inválido: o arquivo de destino não pode ser o mesmo arquivo de origem.");
        return;
    }

    let out = match File::create(destino) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Erro ao criar arquivo de destino '{destino}': {err}");
            return;
        }
    };

    let encrypt_writer = match EncryptWriter::new(out, &senha) {
        Ok(writer) => writer,
        Err(err) => {
            eprintln!("Erro ao iniciar criptografia: {err}");
            return;
        }
    };

    let mut tar = Builder::new(encrypt_writer);

    let entry_name: PathBuf = origem_path
        .file_name()
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("backup"));

    let pack_result = if origem_abs.is_dir() {
        append_dir_resilient(&mut tar, &origem_abs, &entry_name, &destino_abs)
    } else if origem_abs.is_file() {
        tar.append_path_with_name(&origem_abs, &entry_name)
    } else {
        eprintln!("Origem '{origem}' não é arquivo nem diretório regular.");
        return;
    };

    if let Err(err) = pack_result {
        eprintln!("Erro ao empacotar origem '{origem}': {err}");
        return;
    }

    let encrypt_writer = match tar.into_inner() {
        Ok(writer) => writer,
        Err(err) => {
            eprintln!("Erro ao finalizar empacotamento: {err}");
            return;
        }
    };

    let mut out = match encrypt_writer.finish() {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Erro ao finalizar criptografia: {err}");
            return;
        }
    };

    if let Err(err) = out.flush() {
        eprintln!("Erro ao sincronizar arquivo de backup '{destino}': {err}");
        return;
    }

    println!("Backup criptografado criado com sucesso.");
}

fn append_dir_resilient<W: Write>(
    tar: &mut Builder<W>,
    origem_path: &Path,
    root_name: &Path,
    destino_abs: &Path,
) -> Result<(), std::io::Error> {
    let mut skipped = 0usize;

    // Garante a pasta raiz dentro do tar.
    if let Err(err) = tar.append_dir(root_name, origem_path) {
        eprintln!(
            "Aviso: não foi possível adicionar diretório raiz '{}': {}",
            origem_path.display(),
            err
        );
    }

    for entry_result in WalkDir::new(origem_path).follow_links(false) {
        let entry = match entry_result {
            Ok(e) => e,
            Err(err) => {
                skipped += 1;
                eprintln!("Aviso: entrada ignorada durante varredura: {err}");
                continue;
            }
        };

        let full_path = entry.path();
        if full_path == origem_path {
            continue;
        }

        if full_path == destino_abs {
            continue;
        }

        let rel = match full_path.strip_prefix(origem_path) {
            Ok(r) => r,
            Err(_) => {
                skipped += 1;
                eprintln!("Aviso: caminho ignorado (prefixo inválido): {}", full_path.display());
                continue;
            }
        };

        let archive_path = root_name.join(rel);
        let file_type = entry.file_type();

        let result = if file_type.is_dir() {
            tar.append_dir(&archive_path, full_path)
        } else {
            tar.append_path_with_name(full_path, &archive_path)
        };

        if let Err(err) = result {
            skipped += 1;
            eprintln!("Aviso: não foi possível adicionar '{}': {}", full_path.display(), err);
        }
    }

    if skipped > 0 {
        eprintln!("Aviso: {skipped} item(ns) foram ignorados durante o backup.");
    }

    Ok(())
}

fn resolve_destino_abs(destino: &Path) -> Result<PathBuf, std::io::Error> {
    if destino.exists() {
        return fs::canonicalize(destino);
    }

    let parent = destino.parent().unwrap_or_else(|| Path::new("."));
    let parent_abs = fs::canonicalize(parent)?;
    let file_name = destino.file_name().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "destino deve incluir nome de arquivo .enc",
        )
    })?;

    Ok(parent_abs.join(file_name))
}
