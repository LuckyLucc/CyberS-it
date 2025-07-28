import time
import pyautogui
import keyboard

def autoclicker_mouse(interval, button='left', delay=0):
    if delay > 0:
        print(f"Attendi {delay} secondi prima che l'autoclicker inizi...")
        time.sleep(delay)
    print(f"Autoclicker per il mouse (tasto {button}) avviato. Premi 'Q' per fermare.")
    while True:
        if keyboard.is_pressed('q'):
            print("Autoclicker fermato.")
            break
        pyautogui.click(button=button)
        time.sleep(interval / 1000 if interval < 1 else interval)

def autoclicker_keyboard(interval, key, delay=0):
    if delay > 0:
        print(f"Attendi {delay} secondi prima che l'autoclicker inizi...")
        time.sleep(delay)
    print(f"Autoclicker per la tastiera (tasto '{key}') avviato. Premi 'Q' per fermare.")
    while True:
        if keyboard.is_pressed('q'):
            print("Autoclicker fermato.")
            break
        keyboard.press(key)
        keyboard.release(key)
        time.sleep(interval / 1000 if interval < 1 else interval)

def main():
    choice = input("Vuoi usare l'autoclicker per il mouse (M) o per la tastiera (K)? ").lower()
    
    if choice == 'm':
        interval = float(input("Inserisci l'intervallo tra i click (in secondi o millisecondi, es. 0.1 per 100ms): "))
        button = input("Inserisci il tasto del mouse (left, right, middle): ").lower()
        delay = float(input("Inserisci il ritardo iniziale (in secondi): "))
        autoclicker_mouse(interval, button, delay)
    elif choice == 'k':
        interval = float(input("Inserisci l'intervallo tra le pressioni del tasto (in secondi o millisecondi, es. 0.1 per 100ms): "))
        key = input("Inserisci il tasto della tastiera da premere: ")
        delay = float(input("Inserisci il ritardo iniziale (in secondi): "))
        autoclicker_keyboard(interval, key, delay)
    else:
        print("Scelta non valida.")

if __name__ == "__main__":
    main()
