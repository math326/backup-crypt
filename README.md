# **SOBRE BACKUP-CRYPT**

### **Nosso projeto tem como objetivo fazer um backup de suas pastas e arquivos da sua maquina atual usando criptografia AES-256-GCM de senha direta sem KDF dedicado, para seu pendrive.**

### **Isso gera um backup seguro, em casos de roubo ou furto do seu pendrive o hacker não terá ascesso aos seus arquivos e pastas criptografados.**

### **Este backup criptografado foi desenvolvido com a intenção de fazer transferencias de arquivos de um computador para o outro de forma segura, criptografando tudo com uma senha.**



# **COMO USAR O BACKUP-CRYPT:**

## **PRIMEIRO INSTALE O CARGO:**

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

## **AGORA DEIXE O CARGO SEMPRE ATIVO:**

echo 'export PATH="$HOME/.cargo/bin:$PATH"' >> ~/.bashrc && source ~/.bashrc

## **AGORA ENTRE NA PASTA DO PROJETO E COMPILE:**

git clone https://github.com/math326/backup-crypt.git

cd backup-crypt

cargo build --release

## **AGORA PASSE TODOS OS ARQUIVOS DO SEU /home/user PARA O PENDRIVE**

./target/release/vault_rust backup /home/user /media/user/MEU_PENDRIVE/backup_home.enc

## **DEPOIS DE EXECUTAR ESTE COMANDO ELE PEDE UMA SENHA, E ESTA SENHA É A SENHA DA SUA CRIPTOGRAFIA. ANOTE ELA.**


## **E PARA RESTAURAR OS ARQUIVOS E PASTAS CRIPTOGRAFADOS NO PENDRIVE EM OUTRO COMPUTADOR**

./target/release/vault_rust restore /media/user/MEU_PENDRIVE/backup_home.enc /home/user



