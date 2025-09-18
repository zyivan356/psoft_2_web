// script.js
document.addEventListener('DOMContentLoaded', function() {
    // Инициализация при загрузке страницы
    updateReaders('dump');
    updateReaders('encode');
    updateReaders('setup');
    updateReaders('check');
    loadConfig();

    // Регистрируем функцию showStatus как обратный вызов для Python
    eel.expose(showStatus);
});

// Функция переключения вкладок
function openTab(evt, tabName) {
    // Скрыть все вкладки
    var tabcontent = document.getElementsByClassName("tab-content");
    for (var i = 0; i < tabcontent.length; i++) {
        tabcontent[i].classList.remove("active");
    }

    // Убрать активный класс с кнопок
    var tabbuttons = document.getElementsByClassName("tab-button");
    for (var i = 0; i < tabbuttons.length; i++) {
        tabbuttons[i].classList.remove("active");
    }

    // Показать текущую вкладку и добавить "active" класс к кнопке
    document.getElementById(tabName).classList.add("active");
    evt.currentTarget.classList.add("active");
}

// Функция показа статуса
function showStatus(message) {
    const statusDialog = document.getElementById('status-dialog');
    statusDialog.textContent = message;
    statusDialog.style.display = 'block';

    // Автоматически скрываем через 5 секунд
    setTimeout(() => {
        statusDialog.style.display = 'none';
    }, 5000);
}

// Обновление списка считывателей
async function updateReaders(tab) {
    try {
        const readers = await eel.get_readers_list()();
        const selectElement = document.getElementById(`reader-${tab}`);
        selectElement.innerHTML = '';

        if (readers.length > 0 && !readers[0].includes('Ошибка')) {
            readers.forEach(reader => {
                const option = document.createElement('option');
                option.value = reader;
                option.textContent = reader;
                selectElement.appendChild(option);
            });
        } else {
            const option = document.createElement('option');
            option.value = '';
            option.textContent = 'Нет доступных считывателей';
            selectElement.appendChild(option);
        }
    } catch (error) {
        console.error('Ошибка при получении списка считывателей:', error);
        const selectElement = document.getElementById(`reader-${tab}`);
        selectElement.innerHTML = '<option value="">Ошибка загрузки</option>';
    }
}

// Очистка вывода
function clearOutput(elementId) {
    document.getElementById(elementId).textContent = '';
}

// Дамп карты
async function dumpCard() {
    const readerName = document.getElementById('reader-dump').value;
    const outputElement = document.getElementById('dump-output');

    if (!readerName) {
        outputElement.textContent = 'Пожалуйста, выберите считыватель';
        return;
    }

    outputElement.textContent = 'Выполняется дамп карты...\n';

    try {
        const result = await eel.dump_card(readerName)();
        if (result.status === 'success') {
            outputElement.textContent = result.data;
        } else {
            outputElement.textContent = `Ошибка: ${result.error}`;
        }
    } catch (error) {
        outputElement.textContent = `Ошибка: ${error}`;
    }
}

// Очистка всех блоков
async function clearAllBlocks() {
    const readerName = document.getElementById('reader-dump').value;
    const outputElement = document.getElementById('dump-output');

    if (!readerName) {
        outputElement.textContent = 'Пожалуйста, выберите считыватель';
        return;
    }

    // Убираем окно подтверждения
    // if (!confirm('Вы уверены, что хотите очистить все блоки карты?')) {
    //     return;
    // }

    outputElement.textContent = 'Очистка всех блоков...\n';

    try {
        const result = await eel.clear_all_blocks(readerName)();
        if (result.status === 'success') {
            outputElement.textContent = result.data;
        } else {
            outputElement.textContent = `Ошибка: ${result.error}`;
        }
    } catch (error) {
        outputElement.textContent = `Ошибка: ${error}`;
    }
}

// Кодирование
async function encode() {
    const readerName = document.getElementById('reader-encode').value;

    if (!readerName) {
        alert('Пожалуйста, выберите считыватель');
        return;
    }

    try {
        const result = await eel.encode(readerName)();
        if (result.status === 'success') {
            // Успешно, сообщение будет показано через showStatus
        } else {
            alert(`Ошибка: ${result.error}`);
        }
    } catch (error) {
        alert(`Ошибка: ${error}`);
    }
}

// Декодирование
async function decode() {
    const readerName = document.getElementById('reader-encode').value;

    if (!readerName) {
        alert('Пожалуйста, выберите считыватель');
        return;
    }

    try {
        const result = await eel.decode(readerName)();
        if (result.status === 'success') {
            // Успешно, сообщение будет показано через showStatus
        } else {
            alert(`Ошибка: ${result.error}`);
        }
    } catch (error) {
        alert(`Ошибка: ${error}`);
    }
}

// Запись настроечной карты
async function writeSetupCard() {
    const readerName = document.getElementById('reader-setup').value;
    const lockNo = document.getElementById('lock-no').value;
    const waitTime = document.getElementById('wait-time').value;
    const soundMode = document.getElementById('sound-mode').value;
    const alarmMode = document.getElementById('alarm-mode').value;
    const lockMode = document.getElementById('lock-mode').value;
    const cbAuto1 = document.getElementById('cb-auto-1').checked;

    if (!readerName) {
        alert('Пожалуйста, выберите считыватель');
        return;
    }

    try {
        const result = await eel.write_setup_card(
            readerName, lockNo, waitTime, soundMode, alarmMode, lockMode, cbAuto1
        )();

        if (result.status === 'success') {
            // Успешно, сообщение будет показано через showStatus
            // Обновить номер замка, если включён автоинкремент
            if (cbAuto1) {
                document.getElementById('lock-no').value = result.new_lock_no;
            }
        } else {
            alert(`Ошибка: ${result.error}`);
        }
    } catch (error) {
        alert(`Ошибка: ${error}`);
    }
}

// Очистка блоков 60 и 61
async function clearSetupBlocks() {
    const readerName = document.getElementById('reader-setup').value;

    if (!readerName) {
        alert('Пожалуйста, выберите считыватель');
        return;
    }

    // Убираем окно подтверждения
    // if (!confirm('Вы уверены, что хотите очистить блоки 60 и 61?')) {
    //     return;
    // }

    try {
        const result = await eel.clear_setup_blocks(readerName)();
        if (result.status === 'success') {
            // Успешно, сообщение будет показано через showStatus
        } else {
            alert(`Ошибка: ${result.error}`);
        }
    } catch (error) {
        alert(`Ошибка: ${error}`);
    }
}

// Проверка номера замка
async function checkLockNumber() {
    const readerName = document.getElementById('reader-check').value;

    if (!readerName) {
        alert('Пожалуйста, выберите считыватель');
        return;
    }

    try {
        const result = await eel.check_lock_number(readerName)();
        if (result.status === 'success') {
            // Успешно, сообщение будет показано через showStatus
        } else {
            alert(`Ошибка: ${result.error}`);
        }
    } catch (error) {
        alert(`Ошибка: ${error}`);
    }
}

// Загрузка конфигурации
async function loadConfig() {
    try {
        const config = await eel.get_config()();
        document.getElementById('settings-key-a').value = config.default_key_a;
        document.getElementById('settings-key-b').value = config.default_key_b;
        document.getElementById('settings-access-bits').value = config.default_access_bits;
        document.getElementById('settings-block').value = config.default_block;
    } catch (error) {
        console.error('Ошибка при загрузке конфигурации:', error);
    }
}

// Сохранение настроек
async function saveSettings() {
    const keyA = document.getElementById('settings-key-a').value;
    const keyB = document.getElementById('settings-key-b').value;
    const accessBits = document.getElementById('settings-access-bits').value;
    const block = document.getElementById('settings-block').value;

    const statusElement = document.getElementById('settings-status');

    try {
        const result = await eel.save_settings(keyA, keyB, accessBits, block)();
        if (result.status === 'success') {
            statusElement.textContent = result.message;
            statusElement.className = 'success';
        } else {
            statusElement.textContent = result.message;
            statusElement.className = 'error';
        }
    } catch (error) {
        statusElement.textContent = `Ошибка: ${error}`;
        statusElement.className = 'error';
    }
}

// Сброс настроек
async function resetSettings() {
    const statusElement = document.getElementById('settings-status');

    try {
        const result = await eel.reset_settings()();
        if (result.status === 'success') {
            // Обновить поля ввода
            document.getElementById('settings-key-a').value = result.config.default_key_a;
            document.getElementById('settings-key-b').value = result.config.default_key_b;
            document.getElementById('settings-access-bits').value = result.config.default_access_bits;
            document.getElementById('settings-block').value = result.config.default_block;

            statusElement.textContent = result.message;
            statusElement.className = 'success';
        } else {
            statusElement.textContent = result.message;
            statusElement.className = 'error';
        }
    } catch (error) {
        statusElement.textContent = `Ошибка: ${error}`;
        statusElement.className = 'error';
    }
}