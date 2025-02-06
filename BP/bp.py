import tkinter as tk
from tkinter import filedialog, messagebox, Listbox, SINGLE
import zipfile
import threading
import os
import re
from tkinterdnd2 import DND_FILES, TkinterDnD
class ZipCracker:
    def __init__(self, root):
        self.root = root
        self.root.title("ZIP 爆破工具")
        self.root.geometry("600x350")
        self.root.configure(bg="#2C3E50")

        # 标题
        title_label = tk.Label(root, text="ZIP 爆破工具", font=("Arial", 18, "bold"), fg="white", bg="#2C3E50")
        title_label.pack(pady=10)

        # ZIP 文件选择
        tk.Label(root, text="ZIP 文件:", font=("Arial", 12), fg="white", bg="#2C3E50").pack(pady=5)
        self.zip_entry = tk.Entry(root, width=50, font=("Arial", 12))
        self.zip_entry.pack(pady=5)
        self.root.drop_target_register(DND_FILES)
        self.root.dnd_bind('<<Drop>>', self.on_drop)
        tk.Button(root, text="选择 ZIP 文件", command=self.select_zip, font=("Arial", 12), bg="#E74C3C", fg="white").pack(pady=5)

        # 启动按钮
        self.start_button = tk.Button(root, text="开始爆破", command=self.start_cracking, font=("Arial", 14, "bold"), bg="#27AE60", fg="white")
        self.start_button.pack(pady=15)

        # 状态显示
        self.status_label = tk.Label(root, text="等待操作...", font=("Arial", 12), fg="yellow", bg="#2C3E50")
        self.status_label.pack(pady=5)

        # 设定字典路径
        self.dict_file = os.path.join(os.path.dirname(__file__), "rockyou.txt")
        if not os.path.exists(self.dict_file):
            messagebox.showerror("错误", "字典文件 rockyou.txt 未找到！请确保它与脚本在同一目录。")
            self.root.quit()

    def on_drop(self, event):
        file_path = event.data
        self.zip_entry.insert(0, file_path)

    def select_zip(self):
        file_path = filedialog.askopenfilename(filetypes=[("ZIP Files", "*.zip")])
        self.zip_entry.delete(0, tk.END)
        self.zip_entry.insert(0, file_path)

    def crack_zip(self, zip_file):
        try:
            with zipfile.ZipFile(zip_file, 'r') as zf:
                with open(self.dict_file, 'r', encoding='latin-1') as df:
                    for line in df:
                        password = line.strip().encode('latin-1')
                        try:
                            zf.extractall(pwd=password)
                            password_str = password.decode()
                            self.status_label.config(text=f"破解成功！密码: {password_str}", fg="lightgreen")
                            messagebox.showinfo("成功", f"密码找到: {password_str}")
                            
                            # 保存密码到文件
                            zip_name = os.path.basename(zip_file)
                            password_file = os.path.join(os.path.dirname(zip_file), f"{zip_name}的密码.txt")
                            with open(password_file, "w") as pf:
                                pf.write(f"ZIP 文件: {zip_name}\n密码: {password_str}\n")
                            
                            return
                        except (RuntimeError, zipfile.BadZipFile):
                            continue
            self.status_label.config(text="破解失败，未找到密码！", fg="red")
            messagebox.showwarning("失败", "未找到正确的密码。")
        except Exception as e:
            messagebox.showerror("错误", f"出现异常: {str(e)}")

    def start_cracking(self):
        zip_file = self.zip_entry.get()

        if not zip_file:
            messagebox.showwarning("警告", "请选择 ZIP 文件！")
            return

        self.status_label.config(text="正在爆破，请稍候...", fg="orange")

        # 创建新线程执行破解任务，防止GUI卡死
        thread = threading.Thread(target=self.crack_zip, args=(zip_file,))
        thread.start()
 

if __name__ == "__main__":
    # root = tk.Tk()
    root = TkinterDnD.Tk()
    app = ZipCracker(root)
   
    root.mainloop()
