import threading
import time
import ctypes
from smartcard.System import readers
from smartcard.CardMonitoring import CardMonitor, CardObserver
from smartcard.util import toHexString
import win32api
import win32con
import win32gui
import win32clipboard


class RFIDCardObserver(CardObserver):
    def __init__(self, callback=None):
        self.callback = callback

    def update(self, observable, actions):
        (addedcards, removedcards) = actions
        for card in addedcards:
            try:
                # Получаем реальный UID карты
                uid = self.get_real_card_uid(card)
                if uid and self.callback:
                    self.callback(uid)
            except Exception as e:
                pass

    def get_real_card_uid(self, card):
        """Получение реального UID карты с прямым подключением"""
        try:
            # Создаем новое подключение к карте
            from smartcard.System import readers
            reader_list = readers()
            if not reader_list:
                # Если нет считывателей, извлекаем из ATR
                return self.extract_from_atr_fallback(card.atr)

            # Используем первый доступный считыватель
            reader = reader_list[0]
            connection = reader.createConnection()
            connection.connect()

            try:
                # Метод 1: Прямое чтение UID
                get_uid_cmd = [0xFF, 0xCA, 0x00, 0x00, 0x00]  # GET UID
                response, sw1, sw2 = connection.transmit(get_uid_cmd)

                if sw1 == 0x90 and sw2 == 0x00:
                    uid = ''.join([f'{b:02X}' for b in response])
                    return uid
            except:
                pass
            finally:
                try:
                    connection.disconnect()
                except:
                    pass

            # Если прямое чтение не удалось, извлекаем из ATR
            return self.extract_from_atr_fallback(card.atr)

        except Exception as e:
            # Резервный метод - извлечение из ATR
            return self.extract_from_atr_fallback(card.atr)

    def extract_from_atr_fallback(self, atr_bytes):
        """Резервный метод извлечения из ATR"""
        try:
            if len(atr_bytes) >= 8:
                # Наиболее вероятные позиции для UID
                candidates = [
                    ''.join([f'{b:02X}' for b in atr_bytes[1:5]]),  # Позиции 1-4
                    ''.join([f'{b:02X}' for b in atr_bytes[4:8]]),  # Позиции 4-7
                ]

                # Ищем разумный UID
                for candidate in candidates:
                    if (candidate and
                            candidate != "00000000" and
                            candidate != "FFFFFFFF"):
                        return candidate.upper()  # Возвращаем заглавными буквами

                return candidates[0].upper()  # Первый кандидат заглавными

            atr_hex = ''.join([f'{b:02X}' for b in atr_bytes])
            return atr_hex[-8:].upper() if len(atr_hex) >= 8 else atr_hex.upper()
        except:
            return None


class RFIDReader:
    def __init__(self):
        self.card_monitor = None
        self.observer = None
        self.monitoring = False
        self.english_layout = 0x00000409
        self.last_uid = None
        self.last_card_time = 0

    def switch_to_english_temporarily(self):
        """Временное переключение на английский язык"""
        try:
            # Множественные попытки переключения
            for i in range(15):
                try:
                    ctypes.windll.user32.ActivateKeyboardLayout(self.english_layout, 0)
                    ctypes.windll.user32.PostMessageW(0xFFFF, 0x0050, 0, self.english_layout)
                except:
                    pass
                if i < 14:
                    time.sleep(0.0001)
            return True
        except:
            return False

    def input_rfid_via_shift_keys(self, uid):
        """Ввод RFID с удерживанием Shift для заглавных букв"""
        try:
            # Преобразуем UID в заглавные буквы
            uid_upper = uid.upper()

            # Вводим каждый символ с удерживанием Shift для букв
            for char in uid_upper:
                if char.isalnum():
                    vk_code = None
                    if char.isdigit():
                        # Для цифр используем обычные коды
                        vk_code = 0x30 + int(char)  # 0x30 = '0'
                        win32api.keybd_event(vk_code, 0, 0, 0)
                        time.sleep(0.001)
                        win32api.keybd_event(vk_code, 0, win32con.KEYEVENTF_KEYUP, 0)
                        time.sleep(0.001)
                    elif char.isalpha():
                        # Для букв удерживаем Shift
                        vk_code = 0x41 + (ord(char.upper()) - ord('A'))  # 0x41 = 'A'
                        win32api.keybd_event(0x10, 0, 0, 0)  # Shift down
                        time.sleep(0.0005)
                        win32api.keybd_event(vk_code, 0, 0, 0)  # Key down
                        time.sleep(0.001)
                        win32api.keybd_event(vk_code, 0, win32con.KEYEVENTF_KEYUP, 0)  # Key up
                        time.sleep(0.0005)
                        win32api.keybd_event(0x10, 0, win32con.KEYEVENTF_KEYUP, 0)  # Shift up
                        time.sleep(0.001)

            return True
        except Exception as e:
            return False

    def input_rfid_via_clipboard(self, uid):
        """Ввод RFID через буфер обмена (заглавными буквами)"""
        try:
            # Преобразуем UID в заглавные буквы
            uid_upper = uid.upper()

            # Копируем в буфер обмена
            win32clipboard.OpenClipboard()
            win32clipboard.EmptyClipboard()
            win32clipboard.SetClipboardText(uid_upper)
            win32clipboard.CloseClipboard()

            time.sleep(0.005)

            # Ctrl+V
            win32api.keybd_event(0x11, 0, 0, 0)  # Ctrl down
            time.sleep(0.001)
            win32api.keybd_event(0x56, 0, 0, 0)  # V down
            time.sleep(0.001)
            win32api.keybd_event(0x56, 0, win32con.KEYEVENTF_KEYUP, 0)  # V up
            time.sleep(0.001)
            win32api.keybd_event(0x11, 0, win32con.KEYEVENTF_KEYUP, 0)  # Ctrl up

            return True
        except Exception as e:
            return False

    def handle_card_detected(self, uid):
        """Обработчик обнаружения карты"""
        current_time = time.time()

        # Анти-дублирование (1 секунда)
        if uid != self.last_uid or (current_time - self.last_card_time) > 1.0:
            self.last_uid = uid
            self.last_card_time = current_time

            try:
                # Переключаем на английский
                self.switch_to_english_temporarily()

                # Ждем немного
                time.sleep(0.02)  # 20 миллисекунд

                # Пробуем ввести через Shift (для заглавных букв)
                success = self.input_rfid_via_shift_keys(uid)

                if not success:
                    # Если не удалось, пробуем через буфер обмена
                    self.input_rfid_via_clipboard(uid)

            except Exception as e:
                pass

    def start_monitoring(self):
        """Запуск мониторинга карт"""
        if self.monitoring:
            return

        try:
            self.card_monitor = CardMonitor()
            self.observer = RFIDCardObserver(self.handle_card_detected)
            self.card_monitor.addObserver(self.observer)
            self.monitoring = True
        except Exception as e:
            pass

    def stop_monitoring(self):
        """Остановка мониторинга карт"""
        if not self.monitoring:
            return
        try:
            if self.card_monitor and self.observer:
                self.card_monitor.deleteObserver(self.observer)
            self.monitoring = False
        except:
            pass


# Глобальный экземпляр RFID читателя
rfid_reader = RFIDReader()