use std::fs;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use std::collections::HashSet;
use rpassword::prompt_password;
use tar::Archive;

use crate::crypto::DecryptReader;

pub fn run(origem: &str, destino: &str) {

    println!("Senha para descriptografia:");
    let senha = match prompt_password("> ") {
        Ok(senha) => senha,
        Err(err) => {
            eprintln!("Erro ao ler senha: {err}");
            return;
        }
    };

    let file = match File::open(origem) {
        Ok(file) => file,
        Err(err) => {
            eprintln!("Erro ao abrir arquivo criptografado '{origem}': {err}");
            return;
        }
    };

    let decrypt_reader = match DecryptReader::new(file, &senha) {
        Ok(reader) => reader,
        Err(err) => {
            eprintln!("Erro ao iniciar descriptografia: {err}");
            return;
        }
    };

    let destino_path = Path::new(destino);
    if let Err(err) = fs::create_dir_all(destino_path) {
        eprintln!("Erro ao criar diretório de destino '{destino}': {err}");
        return;
    }

    let mut archive = Archive::new(decrypt_reader);
    match restore_with_mapping(&mut archive, destino_path) {
        Ok(_) => println!("Backup restaurado com sucesso."),
        Err(err) => {
            eprintln!("Erro ao restaurar backup em '{destino}': {err}");
        }
    }
}

fn restore_with_mapping<R: Read>(archive: &mut Archive<R>, destino_path: &Path) -> io::Result<()> {
    let mut warned_mismatch: HashSet<String> = HashSet::new();
    let mut warned_missing_system: HashSet<String> = HashSet::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let path_in_archive = entry.path()?.into_owned();

        let Some(rel_path) = strip_archive_root(&path_in_archive) else {
            continue;
        };

        let Some(mapped_rel_path) = map_relative_path(
            rel_path,
            destino_path,
            &mut warned_mismatch,
            &mut warned_missing_system,
        ) else {
            continue;
        };

        let final_path = destino_path.join(mapped_rel_path);
        if let Some(parent) = final_path.parent() {
            fs::create_dir_all(parent)?;
        }

        entry.unpack(&final_path)?;
    }

    Ok(())
}

fn strip_archive_root(path: &Path) -> Option<&Path> {
    let mut comps = path.components();
    comps.next()?;
    let remainder = comps.as_path();
    if remainder.as_os_str().is_empty() {
        None
    } else {
        Some(remainder)
    }
}

fn map_relative_path<'a>(
    rel_path: &'a Path,
    destino_path: &Path,
    warned_mismatch: &mut HashSet<String>,
    warned_missing_system: &mut HashSet<String>,
) -> Option<&'a Path> {
    let mut comps = rel_path.components();
    let first = comps.next()?.as_os_str().to_string_lossy().to_string();

    let Some(group) = system_group_for_name(&first) else {
        // Pasta/arquivo não-sistema: restaura normalmente sem procurar equivalente.
        return Some(rel_path);
    };

    // Para pastas de sistema, exige nome idêntico no destino.
    let same_name_exists = destino_path.join(&first).is_dir();
    if same_name_exists {
        return Some(rel_path);
    }

    let has_other_alias = group
        .iter()
        .any(|alias| alias != &first && destino_path.join(alias).is_dir());

    if has_other_alias {
        if warned_mismatch.insert(first.clone()) {
            eprintln!(
                "Aviso: não foi possível transferir a pasta de sistema '{}': no destino ela tem nome diferente.",
                first
            );
        }
    } else if warned_missing_system.insert(first.clone()) {
        eprintln!(
            "Aviso: pasta de sistema '{}' não encontrada no destino. Conteúdo ignorado.",
            first
        );
    }

    None
}

fn system_group_for_name(name: &str) -> Option<&'static [&'static str]> {
    const GROUPS: &[&[&str]] = &[
        &["Desktop", "Área de Trabalho", "Area de Trabalho"],
        &["Documents", "Documentos"],
        &["Downloads"],
        &["Pictures", "Imagens"],
        &["Music", "Música", "Musica"],
        &["Videos", "Vídeos", "Videos"],
        &["Templates", "Modelos"],
        &["Public", "Público", "Publico"],
    ];

    GROUPS
        .iter()
        .copied()
        .find(|aliases| aliases.iter().any(|alias| alias == &name))
}
