import eel
import json
import os
from smartcard.System import readers
from smartcard.util import toHexString, toBytes
from smartcard.Exceptions import NoCardException, CardConnectionException
from smartcard.CardConnection import CardConnection

# Инициализация Eel
eel.init('web')

# Загрузка конфигурации
config_file = "mifare_config.json"

def load_config():
    """Загрузка конфигурации из файла"""
    default_config = {
        "default_key_a": "FFFFFFFFFFFF",
        "default_key_b": "FFFFFFFFFFFF",
        "default_access_bits": "FF078069",
        "default_block": "62"
    }
    try:
        if os.path.exists(config_file):
            with open(config_file, 'r', encoding='utf-8') as f:
                config = json.load(f)
                # Проверяем, что все нужные поля есть
                for key in default_config:
                    if key not in config:
                        config[key] = default_config[key]
                return config
        else:
            save_config(default_config)
            return default_config
    except Exception as e:
        print(f"Ошибка загрузки конфигурации: {e}")
        return default_config

def save_config(config=None):
    """Сохранение конфигурации в файл"""
    if config is None:
        config = load_config()
    try:
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=4, ensure_ascii=False)
    except Exception as e:
        print(f"Ошибка сохранения конфигурации: {e}")

config = load_config()

def get_readers():
    try:
        return [reader.name for reader in readers()]
    except:
        return ["Ошибка: Не удалось получить список считывателей"]

def get_connection(reader_name):
    try:
        if not reader_name or "Ошибка" in reader_name:
            raise Exception("Выберите корректный считыватель!")
        reader_list = readers()
        reader = next((r for r in reader_list if r.name == reader_name), None)
        if not reader:
            raise Exception("Считыватель не найден!")
        connection = reader.createConnection()
        connection.connect(CardConnection.T1_protocol)
        return connection
    except Exception as e:
        return None

def authenticate(connection, sector, key_type=0x60, custom_key=None):
    try:
        sector = int(sector)
        block_number = sector * 4
        # Используем пользовательский ключ или ключ по умолчанию
        key = toBytes(custom_key) if custom_key else toBytes("FFFFFFFFFFFF")
        # Загрузка ключа в считыватель
        load_key_cmd = [0xFF, 0x82, 0x00, 0x00, 0x06] + key
        response, sw1, sw2 = connection.transmit(load_key_cmd)
        if sw1 != 0x90 or sw2 != 0x00:
            return False
        # Аутентификация
        auth_cmd = [0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, block_number, key_type, 0x00]
        response, sw1, sw2 = connection.transmit(auth_cmd)
        return sw1 == 0x90 and sw2 == 0x00
    except Exception:
        return False

def byte2hex(byte_val):
    """Преобразование байта в hex строку"""
    return f"{byte_val:02X}"

# Eel функции
@eel.expose
def get_readers_list():
    return get_readers()

@eel.expose
def dump_card(reader_name):
    """Функция дампа карты"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        dump = []
        for sector in range(16):
            result["data"] += f"\n--- Сектор {sector} ---\n"
            # Пробуем различные ключи для аутентификации
            auth_success = False
            auth_key = None
            key_type = None
            # Попробуем ключи в порядке приоритета
            key_attempts = [
                ("A", "FFFFFFFFFFFF"),
                ("A", config.get("default_key_a", "FFFFFFFFFFFF")),
                ("B", "FFFFFFFFFFFF"),
                ("B", config.get("default_key_b", "FFFFFFFFFFFF"))
            ]
            for kt, key in key_attempts:
                key_type_code = 0x60 if kt == "A" else 0x61
                if authenticate(connection, sector, key_type_code, key):
                    auth_success = True
                    key_type = kt
                    auth_key = key
                    result["data"] += f"Аутентифицирован с ключом {key_type} ({auth_key})\n"
                    break
            if not auth_success:
                result["data"] += f"Не удалось аутентифицироваться в секторе {sector}\n"
                for block in range(4):
                    block_num = sector * 4 + block
                    dump.append((block_num, None))
                continue
            # Читаем блоки сектора
            for block in range(4):
                block_num = sector * 4 + block
                read_cmd = [0xFF, 0xB0, 0x00, block_num, 16]
                response, sw1, sw2 = connection.transmit(read_cmd)
                if sw1 == 0x90 and sw2 == 0x00:
                    hex_data = toHexString(response)
                    dump.append((block_num, hex_data))
                    result["data"] += f"Блок {block_num:02d}: {hex_data}\n"
                    # Если это трейлерный блок, разбираем его структуру
                    if block == 3:
                        key_a = hex_data[:12]
                        access_bits = hex_data[12:20]
                        key_b = hex_data[20:32]
                        result["data"] += f"  Ключ A: {key_a}\n"
                        result["data"] += f"  Биты доступа: {access_bits}\n"
                        result["data"] += f"  Ключ B: {key_b}\n"
                else:
                    dump.append((block_num, None))
                    result["data"] += f"Блок {block_num:02d}: Ошибка чтения {hex(sw1)} {hex(sw2)}\n"
        result["data"] += "\n--- Полный дамп завершен ---\n"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def clear_all_blocks(reader_name):
    """Очистка всех блоков карты (заполнение нулями)"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        result["data"] += "Начало очистки всех блоков карты...\n"
        # Создаем 16 байт нулей
        zero_data = [0x00] * 16
        result["data"] += f"Данные для очистки: {toHexString(zero_data)}\n"
        success_count = 0
        error_count = 0
        # Очищаем все 64 блока (16 секторов по 4 блока)
        for block_num in range(64):
            sector = block_num // 4
            # Пропускаем трейлерные блоки (3, 7, 11, 15, ...), так как их сложно очистить
            if block_num % 4 == 3:
                result["data"] += f"Пропущен трейлерный блок {block_num} (сектор {sector})\n"
                continue
            try:
                # Аутентификация с ключом A по умолчанию
                if authenticate(connection, sector, 0x60, "FFFFFFFFFFFF"):
                    result["data"] += f"Аутентификация для блока {block_num} (сектор {sector}) успешна\n"
                    # Запись нулевых данных в блок
                    write_cmd = [0xFF, 0xD6, 0x00, block_num, 0x10] + zero_data
                    response, sw1, sw2 = connection.transmit(write_cmd)
                    if sw1 == 0x90 and sw2 == 0x00:
                        result["data"] += f"Блок {block_num} успешно очищен\n"
                        success_count += 1
                    else:
                        result["data"] += f"Ошибка очистки блока {block_num}: {hex(sw1)} {hex(sw2)}\n"
                        error_count += 1
                else:
                    # Пробуем аутентификацию с ключом из настроек
                    if authenticate(connection, sector, 0x60,
                                         config.get("default_key_a", "FFFFFFFFFFFF")):
                        result["data"] += f"Аутентификация для блока {block_num} (сектор {sector}) успешна (ключ из настроек)\n"
                        write_cmd = [0xFF, 0xD6, 0x00, block_num, 0x10] + zero_data
                        response, sw1, sw2 = connection.transmit(write_cmd)
                        if sw1 == 0x90 and sw2 == 0x00:
                            result["data"] += f"Блок {block_num} успешно очищен\n"
                            success_count += 1
                        else:
                            result["data"] += f"Ошибка очистки блока {block_num}: {hex(sw1)} {hex(sw2)}\n"
                            error_count += 1
                    else:
                        result["data"] += f"Ошибка аутентификации для блока {block_num} (сектор {sector})\n"
                        error_count += 1
            except Exception as e:
                result["data"] += f"Ошибка при обработке блока {block_num}: {e}\n"
                error_count += 1
        result["data"] += f"\nОчистка завершена. Успешно: {success_count}, Ошибок: {error_count}\n"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def encode(reader_name):
    """Функция кодирования (записи ключей)"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        # Определение сектора и трейлерного блока на основе выбранного блока
        block = int(config.get("default_block", "62"))
        if block not in [33, 62]:
            raise Exception("Номер блока по умолчанию должен быть 33 или 62")
        if block == 62:
            sector = 15
            trailer_block = 63  # Трейлерный блок сектора 15
        elif block == 33:
            sector = 8
            trailer_block = 35  # Трейлерный блок сектора 8
        key_a = config.get("default_key_a", "FFFFFFFFFFFF")
        access_bits = config.get("default_access_bits", "FF078069")
        key_b = config.get("default_key_b", "FFFFFFFFFFFF")
        new_data = toBytes(key_a + access_bits + key_b)
        result["data"] += f"Попытка записи в блок {trailer_block} (сектор {sector})\n"
        result["data"] += f"Данные для записи: {toHexString(new_data)}\n"
        result["data"] += f"Новый ключ A: {key_a}\n"
        # Пробуем аутентифицироваться с ключом по умолчанию (старый ключ)
        auth_success = False
        if authenticate(connection, sector, 0x60, "FFFFFFFFFFFF"):
            result["data"] += "Аутентификация с ключом FFFFFFFFFFFFFF успешна\n"
            auth_success = True
        # Пробуем аутентифицироваться с текущим ключом из настроек
        elif authenticate(connection, sector, 0x60, key_a):
            result["data"] += f"Аутентификация с пользовательским ключом {key_a} успешна\n"
            auth_success = True
        if not auth_success:
            result["status"] = "error"
            result["error"] = "Не удалось аутентифицироваться ни с одним ключом"
            return result
        # Выполняем запись
        write_cmd = [0xFF, 0xD6, 0x00, trailer_block, 0x10] + new_data
        response, sw1, sw2 = connection.transmit(write_cmd)
        if sw1 == 0x90 and sw2 == 0x00:
            result["data"] += f"Данные успешно записаны в блок {trailer_block}\n"
            result["data"] += f"Ключ A: {key_a}\n"
            result["data"] += f"Биты доступа: {access_bits}\n"
            result["data"] += f"Ключ B: {key_b}\n"
            # Проверяем, что новый ключ работает, сразу после записи
            if authenticate(connection, sector, 0x60, key_a):
                result["data"] += "Новый ключ успешно работает для аутентификации\n"
                # Отправляем сообщение в JavaScript через обратный вызов
                eel.showStatus(f"Карта закодирована паролем: {key_a}") # <-- Используем eel.showStatus
            else:
                result["data"] += "ВНИМАНИЕ: Новый ключ не работает для аутентификации!\n"
        else:
            result["status"] = "error"
            result["error"] = f"Ошибка записи: {hex(sw1)} {hex(sw2)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def decode(reader_name):
    """Функция декодирования (восстановления ключа FFFFFFFFFFFF)"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        # Определение сектора и трейлерного блока на основе выбранного блока
        block = int(config.get("default_block", "62"))
        if block not in [33, 62]:
            raise Exception("Номер блока по умолчанию должен быть 33 или 62")
        if block == 62:
            sector = 15
            trailer_block = 63  # Трейлерный блок сектора 15
        elif block == 33:
            sector = 8
            trailer_block = 35  # Трейлерный блок сектора 8
        key_a = "FFFFFFFFFFFF"  # Восстанавливаем ключ F
        access_bits = config.get("default_access_bits", "FF078069")
        key_b = "FFFFFFFFFFFF"  # Восстанавливаем ключ F
        new_data = toBytes(key_a + access_bits + key_b)
        result["data"] += f"Попытка записи ключей F в блок {trailer_block} (сектор {sector})\n"
        result["data"] += f"Данные для записи: {toHexString(new_data)}\n"
        # Пробуем аутентифицироваться с текущим ключом из настроек
        current_key = config.get("default_key_a", "FFFFFFFFFFFF")
        if authenticate(connection, sector, 0x60, current_key):
            result["data"] += f"Аутентификация с текущим ключом {current_key} успешна\n"
            auth_key = current_key
        # Пробуем аутентифицироваться с ключом F
        elif authenticate(connection, sector, 0x60, "FFFFFFFFFFFF"):
            result["data"] += "Аутентификация с ключом FFFFFFFFFFFFFF успешна\n"
            auth_key = "FFFFFFFFFFFF"
        else:
            result["status"] = "error"
            result["error"] = "Не удалось аутентифицироваться"
            return result
        # Выполняем запись ключей F
        write_cmd = [0xFF, 0xD6, 0x00, trailer_block, 0x10] + new_data
        response, sw1, sw2 = connection.transmit(write_cmd)
        if sw1 == 0x90 and sw2 == 0x00:
            result["data"] += f"Ключи F успешно записаны в блок {trailer_block}\n"
            result["data"] += f"Ключ A: {key_a}\n"
            result["data"] += f"Биты доступа: {access_bits}\n"
            result["data"] += f"Ключ B: {key_b}\n"
            # Проверяем, что ключ F работает
            if authenticate(connection, sector, 0x60, "FFFFFFFFFFFF"):
                result["data"] += "Ключ F успешно работает\n"
                # Отправляем сообщение в JavaScript через обратный вызов
                eel.showStatus("Карта успешно декодирована") # <-- Используем eel.showStatus
            else:
                result["data"] += "ВНИМАНИЕ: Ключ F не работает!\n"
        else:
            result["status"] = "error"
            result["error"] = f"Ошибка записи: {hex(sw1)} {hex(sw2)}"
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def write_setup_card(reader_name, lock_no, wait_time, sound_mode, alarm_mode, lock_mode, cb_auto_1):
    """Запись настроечной карты (аналог Delphi кода) с фиксированным паролем FFFFFFFFFFFF"""
    result = {"status": "success", "data": "", "error": "", "new_lock_no": lock_no}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        # Получение параметров
        try:
            lock_no = int(lock_no)
            wait_time = int(wait_time)
        except ValueError:
            result["status"] = "error"
            result["error"] = "Ошибка: Неверный формат номера замка или времени"
            return result
        # Используем фиксированный пароль FFFFFFFFFFFF для настроечной карты
        password = "FFFFFFFFFFFF"
        result["data"] += f"Используется фиксированный пароль: {password}\n"
        # Проверка валидности пароля
        if len(password) != 12 or not all(c in "0123456789ABCDEF" for c in password):
            result["status"] = "error"
            result["error"] = "Ошибка: Пароль должен содержать 12 hex символов"
            return result
        # Получаем режим замка
        lock_mode = int(lock_mode)
        if lock_mode == 0:
            # Нормальный режим - формируем данные как раньше
            s = "AA"
            # Формирование байта флагов
            b = 0
            b |= 0x10  # Установка бита 4
            b |= 0x20  # Установка бита 5
            # Режим звука
            sound_mode = int(sound_mode)
            if sound_mode == 1:
                b |= 0x02
            elif sound_mode == 2:
                b |= 0x01
            elif sound_mode == 3:
                b |= 0x03
            # Режим тревоги
            alarm_mode = int(alarm_mode)
            if alarm_mode == 1:
                b |= 0x80
            elif alarm_mode == 2:
                b |= 0xC0
            s += byte2hex(b)
            s += "AA"
            # Режим замка (нормальный)
            s += byte2hex(0)
            # Время ожидания
            s += byte2hex(wait_time & 0xFF)
            s += "00"
            # Номер замка - записываем в правильном порядке (little-endian)
            cabno = lock_no & 0xFFFF
            s += byte2hex(cabno & 0xFF)  # LoByte первым
            s += byte2hex((cabno >> 8) & 0xFF)  # HiByte вторым
            # Фиксированный пароль
            s += password
            s += "00"
            result["data"] += f"Формирование данных для блока 61 (нормальный режим): {s}\n"
            # Преобразование в байты
            data_block_61 = toBytes(s)
            # Данные для блока 60 (нормальный режим)
            data_block_60_hex = "484E31394D2D31000000000000000000"
            data_block_60 = toBytes(data_block_60_hex)
        else:
            # Специальный режим - используем точные данные как в примерах
            result["data"] += "Используется специальный режим записи\n"
            # Блок 60: 484E31394D2D31000000000000000000
            data_block_60_hex = "484E31394D2D31000000000000000000"
            data_block_60 = toBytes(data_block_60_hex)
            # Блок 61: AA32AA020600[номер_замка]00[9F792063F24B3E00]
            # Например для замка 2: AA32AA02060002009F792063F24B3E00
            # Для замка 3: AA32AA02060003009F792063F24B3E00
            # Формируем блок 61
            header = "AA32AA020600"
            # Номер замка (1 байт) + 00
            lock_byte = byte2hex(lock_no & 0xFF)  # Номер замка как один байт
            middle = lock_byte + "00"
            # Остальная часть данных (изменено)
            footer = "9F792063F24B3E00"
            data_block_61_hex = header + middle + footer
            data_block_61 = toBytes(data_block_61_hex)
            result["data"] += f"Данные блок 60 (специальный): {data_block_60_hex}\n"
            result["data"] += f"Данные блок 61 (специальный): {data_block_61_hex}\n"
            result["data"] += f"Номер замка: {lock_no} (0x{lock_no:02X})\n"
        result["data"] += f"Данные блок 61: {toHexString(data_block_61)}\n"
        result["data"] += f"Данные блок 60: {toHexString(data_block_60)}\n"
        # Запись в блок 61
        sector_61 = 61 // 4  # Сектор 15
        if authenticate(connection, sector_61, 0x60, "FFFFFFFFFFFF"):
            result["data"] += "Аутентификация для блока 61 успешна\n"
            write_cmd = [0xFF, 0xD6, 0x00, 61, 0x10] + list(data_block_61)
            response, sw1, sw2 = connection.transmit(write_cmd)
            if sw1 == 0x90 and sw2 == 0x00:
                result["data"] += "Данные успешно записаны в блок 61\n"
            else:
                result["status"] = "error"
                result["error"] = f"Ошибка записи в блок 61: {hex(sw1)} {hex(sw2)}"
                return result
        else:
            result["status"] = "error"
            result["error"] = "Ошибка аутентификации для блока 61"
            return result
        # Запись в блок 60
        sector_60 = 60 // 4  # Сектор 15
        if authenticate(connection, sector_60, 0x60, "FFFFFFFFFFFF"):
            result["data"] += "Аутентификация для блока 60 успешна\n"
            write_cmd = [0xFF, 0xD6, 0x00, 60, 0x10] + list(data_block_60)
            response, sw1, sw2 = connection.transmit(write_cmd)
            if sw1 == 0x90 and sw2 == 0x00:
                result["data"] += "Данные успешно записаны в блок 60\n"
            else:
                result["status"] = "error"
                result["error"] = f"Ошибка записи в блок 60: {hex(sw1)} {hex(sw2)}"
                return result
        else:
            result["status"] = "error"
            result["error"] = "Ошибка аутентификации для блока 60"
            return result
        # Успешное завершение
        result["data"] += f"Карта успешно записана. Замок: {lock_no}\n"
        # Отправляем сообщение в JavaScript через обратный вызов
        eel.showStatus(f"Настроечная карта успешно записана, номер замка {lock_no}") # <-- Используем eel.showStatus
        # Автоинкремент номера замка
        if cb_auto_1:
            new_lock_no = lock_no + 1
            result["new_lock_no"] = new_lock_no
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def clear_setup_blocks(reader_name):
    """Очистка блоков 60 и 61 (заполнение нулями) с паролем из конфигурации"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        # Используем пароль из конфигурации для АУТЕНТИФИКАЦИИ
        config_password = config.get("default_key_a", "FFFFFFFFFFFF")
        result["data"] += f"Используется пароль из конфигурации для аутентификации: {config_password}\n"
        # Создаем 16 байт нулей
        zero_data = [0x00] * 16
        result["data"] += "Очистка блоков 60 и 61\n"
        result["data"] += f"Данные для очистки: {toHexString(zero_data)}\n"
        # Очистка блока 61 - используем пароль из конфигурации для АУТЕНТИФИКАЦИИ
        sector_61 = 61 // 4  # Сектор 15
        if authenticate(connection, sector_61, 0x60, config_password):
            result["data"] += "Аутентификация для блока 61 успешна\n"
            write_cmd = [0xFF, 0xD6, 0x00, 61, 0x10] + zero_data
            response, sw1, sw2 = connection.transmit(write_cmd)
            if sw1 == 0x90 and sw2 == 0x00:
                result["data"] += "Блок 61 успешно очищен\n"
            else:
                result["status"] = "error"
                result["error"] = f"Ошибка очистки блока 61: {hex(sw1)} {hex(sw2)}"
                return result
        else:
            # Пробуем аутентификацию с фиксированным ключом FFFFFFFFFFFF
            if authenticate(connection, sector_61, 0x60, "FFFFFFFFFFFF"):
                result["data"] += "Аутентификация для блока 61 успешна (фиксированный ключ)\n"
                write_cmd = [0xFF, 0xD6, 0x00, 61, 0x10] + zero_data
                response, sw1, sw2 = connection.transmit(write_cmd)
                if sw1 == 0x90 and sw2 == 0x00:
                    result["data"] += "Блок 61 успешно очищен\n"
                else:
                    result["status"] = "error"
                    result["error"] = f"Ошибка очистки блока 61: {hex(sw1)} {hex(sw2)}"
                    return result
            else:
                result["status"] = "error"
                result["error"] = "Ошибка аутентификации для блока 61"
                return result
        # Очистка блока 60 - используем пароль из конфигурации для АУТЕНТИФИКАЦИИ
        sector_60 = 60 // 4  # Сектор 15
        if authenticate(connection, sector_60, 0x60, config_password):
            result["data"] += "Аутентификация для блока 60 успешна\n"
            write_cmd = [0xFF, 0xD6, 0x00, 60, 0x10] + zero_data
            response, sw1, sw2 = connection.transmit(write_cmd)
            if sw1 == 0x90 and sw2 == 0x00:
                result["data"] += "Блок 60 успешно очищен\n"
            else:
                result["status"] = "error"
                result["error"] = f"Ошибка очистки блока 60: {hex(sw1)} {hex(sw2)}"
                return result
        else:
            # Пробуем аутентификацию с фиксированным ключом FFFFFFFFFFFF
            if authenticate(connection, sector_60, 0x60, "FFFFFFFFFFFF"):
                result["data"] += "Аутентификация для блока 60 успешна (фиксированный ключ)\n"
                write_cmd = [0xFF, 0xD6, 0x00, 60, 0x10] + zero_data
                response, sw1, sw2 = connection.transmit(write_cmd)
                if sw1 == 0x90 and sw2 == 0x00:
                    result["data"] += "Блок 60 успешно очищен\n"
                else:
                    result["status"] = "error"
                    result["error"] = f"Ошибка очистки блока 60: {hex(sw1)} {hex(sw2)}"
                    return result
            else:
                result["status"] = "error"
                result["error"] = "Ошибка аутентификации для блока 60"
                return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def check_lock_number(reader_name):
    """Проверка номера замка в блоке 62"""
    result = {"status": "success", "data": "", "error": ""}
    connection = get_connection(reader_name)
    if not connection:
        result["status"] = "error"
        result["error"] = "Ошибка подключения к считывателю"
        return result
    try:
        result["data"] += "Проверка номера замка в блоке 62...\n"
        # Блок 62 находится в секторе 15
        sector = 15
        block_num = 62
        # --- Определяем, какой ключ использовать для аутентификации сектора 15 ---
        # Сначала пробуем стандартный ключ 'FFFFFFFFFFFF' (как для настроечных карт)
        auth_key = "FFFFFFFFFFFF"
        key_type = 0x60  # Ключ A
        if not authenticate(connection, sector, key_type, auth_key):
            # Если стандартный ключ не подошёл, пробуем ключ A из настроек
            auth_key = config.get("default_key_a", "FFFFFFFFFFFF")
            if not authenticate(connection, sector, key_type, auth_key):
                result["status"] = "error"
                result["error"] = f"Ошибка аутентификации сектора {sector} для чтения блока {block_num}. Пробовали ключи: FFFFFFFFFFFF, {config.get('default_key_a', 'N/A')}"
                return result
            else:
                result["data"] += f"Аутентификация успешна с ключом из настроек: {auth_key}\n"
        else:
            result["data"] += "Аутентификация успешна с ключом FFFFFFFFFFFF\n"
        # --- Читаем блок 62 ---
        read_cmd = [0xFF, 0xB0, 0x00, block_num, 16]
        response, sw1, sw2 = connection.transmit(read_cmd)
        if sw1 == 0x90 and sw2 == 0x00:
            hex_data = toHexString(response)
            result["data"] += f"Данные из блока {block_num}: {hex_data}\n"
            # --- Анализируем данные блока 62 ---
            # Судя по вашему описанию: "здесь записан замок номер 5, там где 5"
            # "0000000005000000 484E313908060000"
            # Номер замка 5 находится в 5-м байте (индекс 4), значение 0x05.
            # Предыдущая логика была для блока 61. Адаптируем для блока 62.
            if len(response) >= 5:  # Нужно минимум 5 байт
                # Предполагаем, что номер замка - это один байт по смещению 4
                lock_number_byte = response[4]
                result["data"] += f"Номер замка (из байта 4): {lock_number_byte}\n"
                result["data"] += f"  Байт: 0x{lock_number_byte:02X} ({lock_number_byte})\n"
                # Отправляем сообщение в JavaScript через обратный вызов
                eel.showStatus(f"Закрыт замок {lock_number_byte}") # <-- Используем eel.showStatus
            else:
                result["status"] = "error"
                result["error"] = "Ошибка: Недостаточно данных в блоке 62 для извлечения номера замка"
                return result
        else:
            result["status"] = "error"
            result["error"] = f"Ошибка чтения блока {block_num}: {hex(sw1):0>2X} {hex(sw2):0>2X}"
            return result
    except Exception as e:
        result["status"] = "error"
        result["error"] = f"Ошибка: {e}"
    finally:
        try:
            connection.disconnect()
        except:
            pass
    return result

@eel.expose
def get_config():
    return config

@eel.expose
def save_settings(key_a, key_b, access_bits, block):
    """Сохранение настроек"""
    global config
    try:
        # Проверка валидности данных
        key_a = key_a.strip().upper()
        key_b = key_b.strip().upper()
        access_bits = access_bits.strip().upper()
        block = block.strip()
        if len(key_a) != 12 or not all(c in "0123456789ABCDEF" for c in key_a):
            raise Exception("Ключ A должен содержать ровно 12 hex символов (0-9, A-F)")
        if len(key_b) != 12 or not all(c in "0123456789ABCDEF" for c in key_b):
            raise Exception("Ключ B должен содержать ровно 12 hex символов (0-9, A-F)")
        if len(access_bits) != 8 or not all(c in "0123456789ABCDEF" for c in access_bits):
            raise Exception("Биты доступа должны содержать ровно 8 hex символов (0-9, A-F)")
        block_num = int(block)
        if block_num not in [33, 62]:
            raise Exception("Номер блока по умолчанию должен быть 33 или 62")
        # Обновление конфигурации
        config["default_key_a"] = key_a
        config["default_key_b"] = key_b
        config["default_access_bits"] = access_bits
        config["default_block"] = block
        # Сохранение в файл
        save_config(config)
        return {"status": "success", "message": "Настройки сохранены успешно!"}
    except Exception as e:
        return {"status": "error", "message": f"Ошибка: {e}"}

@eel.expose
def reset_settings():
    """Сброс настроек к значениям по умолчанию"""
    global config
    default_config = {
        "default_key_a": "FFFFFFFFFFFF",
        "default_key_b": "FFFFFFFFFFFF",
        "default_access_bits": "FF078069",
        "default_block": "62"
    }
    config = default_config
    save_config(config)
    return {"status": "success", "message": "Настройки сброшены к значениям по умолчанию", "config": config}

# Запуск приложения
if __name__ == '__main__':
    eel.start('index.html', size=(1200, 800))