import win32api
import win32con
import win32gui
import win32ui
from PIL import Image
import sys

def extract_icon(exe_path, output_path):
    large_icons, _ = win32gui.ExtractIconEx(exe_path, 0)
    if not large_icons:
        print("No icon found in the executable.")
        return

    hicon = large_icons[0]
    hdc = win32ui.CreateDCFromHandle(win32gui.GetDC(0))
    hbmp = win32ui.CreateBitmap()

    # Define the icon size (usually 32x32 or 64x64)
    icon_width, icon_height = 32, 32
    hbmp.CreateCompatibleBitmap(hdc, icon_width, icon_height)

    memdc = hdc.CreateCompatibleDC()
    memdc.SelectObject(hbmp)

    # Draw the icon into the bitmap
    win32gui.DrawIcon(memdc.GetSafeHdc(), 0, 0, hicon)
    
    # Convert the bitmap to an image
    bmpinfo = hbmp.GetInfo()
    bmpstr = hbmp.GetBitmapBits(True)
    img = Image.frombuffer('RGB', (bmpinfo['bmWidth'], bmpinfo['bmHeight']), bmpstr, 'raw', 'BGRX', 0, 1)
    
    img.save(output_path)
    print(f"Icon saved to {output_path}")

    # Clean up GDI resources
    win32gui.DestroyIcon(hicon)
    memdc.DeleteDC()
    hdc.DeleteDC()


exe_path = "tools/reverse/Cheat Engine 7.5/Cheat Engine.exe"
output_path = "tools/reverse/Cheat Engine 7.5/icon.png"
# exe_path = sys.argv[1]
# output_path = sys.argv[2]
print(exe_path, output_path)
extract_icon(exe_path, output_path)