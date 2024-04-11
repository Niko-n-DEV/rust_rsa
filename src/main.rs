use std::fs::{self, File, OpenOptions};
use std::io::prelude::*;
use std::io::{self, BufReader};
use std::sync::Arc;
use std::thread;
use std::time::UNIX_EPOCH;

use rsa::{Pkcs1v15Encrypt, RsaPrivateKey};

struct CryptoKey {
    private_key: RsaPrivateKey,
}

impl CryptoKey {
    fn new() -> Self {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), BITS)
            .expect("Ошибка генерации закрытого ключа");
        Self { private_key }
    }
}

fn main() -> io::Result<()> {
    let key = Arc::new(CryptoKey::new());

    // получение метаданных файла для сверки
    let mut last_modified = match fs::metadata("input.txt") {
        Ok(metadata) => metadata
            .modified()
            .unwrap_or_else(|_| {
                panic!("Ошибка при получении времени последнего изменения файла");
            })
            .duration_since(UNIX_EPOCH)
            .unwrap_or_else(|_| {
                panic!("Ошибка при получении времени последнего изменения файла");
            })
            .as_secs(),
        Err(e) => {
            panic!("Ошибка при получении метаданных файла: {}", e);
        }
    };

    let mut first_launch: bool = true;

    loop {
        let crypto_keys_clone = Arc::clone(&key);

        let current_modified = match fs::metadata("input.txt") {
            Ok(metadata) => metadata
                .modified()
                .unwrap_or_else(|_| {
                    panic!("Ошибка при получении времени последнего изменения файла");
                })
                .duration_since(UNIX_EPOCH)
                .unwrap_or_else(|_| {
                    panic!("Ошибка при получении времени последнего изменения файла");
                })
                .as_secs(),
            Err(e) => {
                eprintln!("Ошибка при получении метаданных файла: {}", e);
                continue;
            }
        };

        if current_modified != last_modified || first_launch {
            first_launch = false;
            // Создаем поток для обработки входящих данных
            let handle = thread::spawn(move || {
                // Открытие файла для чтения входящих данных
                let input_file = File::open("input.txt").expect("Не удалось открыть файл ввода");
                let reader = io::BufReader::new(input_file);

                // Обрабатываем каждую строку из файла
                for line in reader.lines() {
                    let input_data = line.expect("Ошибка чтения строки");
                    println!("Полученные данные: {}", input_data);
                    // Вызов функции для шифровки данных и запись в файл
                    encrypt_and_write(&input_data, &crypto_keys_clone)
                        .expect("Ошибка шифрования и записи в файл");
                }
            });

            // Ожидание завершения обработки входящих данных
            handle.join().unwrap();

            // Вызов функции для обработки зашифрованных данных и их запись в файл для дешифрованных данных
            decrypt_and_write(&key).expect("Ошибка дешифрования и записи в файл");

            // Обновляем время последнего изменения файла
            last_modified = current_modified;

            // Пауза перед следующей итерацией, чтобы не перегружать процессор
            thread::sleep(std::time::Duration::from_secs(5));
        }
    }
}

const BITS: usize = 2048; // Размер ключа для шифровки и дешифровки

/// Функция для обработки входных данных и их шифрование
fn encrypt_and_write(input_data: &str, key_struct: &Arc<CryptoKey>) -> io::Result<()> {
    // Генерация ключей
    let private_key = key_struct.private_key.clone();
    let public_key = private_key.to_public_key();

    // Шифрование данных
    let encrypted_message = public_key
        .encrypt(
            &mut rand::thread_rng(),
            Pkcs1v15Encrypt,
            input_data.as_bytes(),
        )
        .expect("Ошибка шифрования");

    // Запись зашифрованных данных в файл
    let mut output_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("encrypted.txt")?;
    output_file.write_all(&encrypted_message)?;

    Ok(())
}

/// Функция для обработки входных данных и их дешифрование
fn decrypt_and_write(key_struct: &Arc<CryptoKey>) -> io::Result<()> {
    // Открытие файла с зашифрованными данными
    let input_file = File::open("encrypted.txt")?;
    let reader = BufReader::new(input_file);

    // Открытие файла для записи дешифрованных данных
    let mut output_file = OpenOptions::new()
        .create(true)
        .append(true)
        .open("decrypted.txt")?;

    // Дешифрование данных и запись в файл
    for line in reader.lines() {
        let encrypted_data = line.unwrap_or_else(|err| {
            eprintln!("Ошибка чтения зашифрованных данных: {}", err);
            return String::new(); // Продолжаем выполнение программы, возвращая пустую строку
        });

        // Дешифрование данных
        let private_key = key_struct.private_key.clone();
        let decrypted_message = private_key
            .decrypt(Pkcs1v15Encrypt, encrypted_data.as_bytes())
            .unwrap_or_else(|err| {
                eprintln!("Ошибка дешифрования данных: {}", err);
                return Vec::new(); // Продолжаем выполнение программы, возвращая пустой вектор байт
            });

        // Запись дешифрованных данных в файл
        if let Err(e) = output_file.write_all(&decrypted_message) {
            eprintln!("Ошибка записи дешифрованных данных в файл: {}", e);
        }
    }

    Ok(())
}

//#[test]
/// Первый тестовый код
fn first_test_code() {
    let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), BITS)
        .expect("Ошибка генерации закрытого ключа");
    let public_key = private_key.to_public_key();

    // Текст для шифрования
    let message = "Hello, RSA!";
    let message = message.as_bytes();

    // Шифрование
    let encrypted_message = public_key
        .encrypt(&mut rand::thread_rng(), Pkcs1v15Encrypt, message)
        .expect("Ошибка шифрования");

    // Дешифрование
    let decrypted_message = private_key
        .decrypt(Pkcs1v15Encrypt, &encrypted_message)
        .expect("Ошибка дешифрования");
    let decrypted_message =
        String::from_utf8(decrypted_message).expect("Ошибка конвертации в строку");

    println!("Исходное сообщение: {}", String::from_utf8_lossy(message));
    println!("Зашифрованное сообщение: {:?}", encrypted_message);
    println!("Дешифрованное сообщение: {}", decrypted_message);
}
