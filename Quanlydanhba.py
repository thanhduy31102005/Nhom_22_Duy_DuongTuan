import tkinter as tk
from tkinter import messagebox, ttk
import json
import os
import requests
import re
import hashlib
from datetime import datetime
import tempfile
from PIL import Image, ImageTk
import random

class ContactManagerApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Quản Lý Danh Bạ")
        self.root.geometry("900x650")
        self.root.resizable(True, True)
        self.root.minsize(600, 400)
        self.current_user = None
        self.user_role = None
        self.temp_image_path = None
        
        # Cấu hình màu sắc
        self.bg_color = "#f5f7fa"
        self.primary_color = "#007bff"
        self.secondary_color = "#6c757d"
        self.logout_color = "#f39c12"
        self.text_color = "#212529"
        self.border_color = "#dee2e6"
        self.accent_color = "#28a745"
        self.root.configure(bg=self.bg_color)
        
        # Cấu hình style
        self.style = ttk.Style()
        self.style.theme_use("clam")
        
        self.style.configure("TLabel", font=("Segoe UI", 12), background=self.bg_color, foreground=self.text_color)
        self.style.configure("TButton", font=("Segoe UI", 12, "bold"), padding=12, background=self.primary_color, foreground="white")
        self.style.map("TButton", background=[("active", "#0052cc")])
        self.style.configure("TEntry", fieldbackground="white", font=("Segoe UI", 14), padding=12, borderwidth=1)
        self.style.configure("Treeview", font=("Segoe UI", 10), rowheight=25, background="white", fieldbackground="white")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 11, "bold"), background=self.primary_color, foreground="white")
        self.style.map("Treeview.Heading", background=[("active", "#0052cc")])
        self.style.configure("TLabelframe", background=self.bg_color)
        self.style.configure("TLabelframe.Label", font=("Segoe UI", 12, "bold"), background=self.bg_color, foreground=self.text_color)
        
        self.style.configure("Admin.TButton", background="#e74c3c", font=("Segoe UI", 10, "bold"))
        self.style.map("Admin.TButton", background=[("active", "#c0392b")])
        
        self.style.configure("Logout.TButton", background=self.logout_color, font=("Segoe UI", 10, "bold"))
        self.style.map("Logout.TButton", background=[("active", "#e67e22")])
        
        self.style.configure("Login.TButton", font=("Segoe UI", 16, "bold"), padding=15, background=self.primary_color, foreground="white", borderwidth=0)
        self.style.map("Login.TButton", 
                      background=[("active", "#0052cc")],
                      relief=[("pressed", "flat"), ("!pressed", "flat")])
        self.style.configure("SecondaryLogin.TButton", font=("Segoe UI", 14), padding=12, background="white", foreground=self.secondary_color, borderwidth=0)
        self.style.map("SecondaryLogin.TButton", 
                      foreground=[("active", "#003d99")],
                      relief=[("pressed", "flat"), ("!pressed", "flat")])
        self.style.configure("Login.TEntry", fieldbackground="white", font=("Segoe UI", 14), padding=12, borderwidth=1)
        self.style.map("Login.TEntry", 
                      relief=[("focus", "solid"), ("!focus", "solid")],
                      selectbackground=[("focus", "#e6f0ff")],
                      selectforeground=[("focus", self.text_color)],
                      highlightcolor=[("focus", self.primary_color), ("!focus", self.border_color)],
                      highlightthickness=[("focus", 1), ("!focus", 1)])

        self.load_default_image()
        self.contacts_file = "contacts.json"
        self.users_file = "users.json"
        self.initialize_files()
        self.create_login_screen()
        
        self.root.bind("<Configure>", self.on_resize)

    def on_resize(self, event):
        if hasattr(self, 'current_canvas'):
            width = event.width
            height = event.height
            self.current_canvas.config(width=width, height=height)
            self.current_canvas.delete("all")
            for i in range(height):
                r = int(245 + (255-245) * (i/height))
                g = int(247 + (255-247) * (i/height))
                b = int(250 + (255-250) * (i/height))
                color = f"#{r:02x}{g:02x}{b:02x}"
                self.current_canvas.create_line(0, i, width, i, fill=color)

    def load_default_image(self):
        try:
            local_image_path = "images.jpg"  
            img = Image.open(local_image_path)
            img = img.resize((80, 80), Image.Resampling.LANCZOS)
            self.default_image = ImageTk.PhotoImage(img)
        except Exception as e:
            messagebox.showwarning("Cảnh báo", f"Lỗi khi tải ảnh mặc định: {str(e)}. Sử dụng placeholder.")
            self.default_image = None

    def cleanup(self):
        if self.temp_image_path and os.path.exists(self.temp_image_path):
            os.remove(self.temp_image_path)

    def initialize_files(self):
        if not os.path.exists(self.contacts_file):
            with open(self.contacts_file, 'w') as f:
                json.dump([], f)
        else:
            try:
                with open(self.contacts_file, 'r') as f:
                    data = json.load(f)
                if not isinstance(data, list):
                    with open(self.contacts_file, 'w') as f:
                        json.dump([], f)
            except json.JSONDecodeError:
                with open(self.contacts_file, 'w') as f:
                    json.dump([], f)
                
        if not os.path.exists(self.users_file):
            admin = {
                "username": "admin",
                "password": hashlib.md5("admin123".encode()).hexdigest(),
                "role": "admin"
            }
            with open(self.users_file, 'w') as f:
                json.dump([admin], f)
        else:
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
                if not any(user['username'] == "admin" for user in users):
                    admin = {
                        "username": "admin",
                        "password": hashlib.md5("admin123".encode()).hexdigest(),
                        "role": "admin"
                    }
                    users.append(admin)
                    with open(self.users_file, 'w') as f:
                        json.dump(users, f, indent=2)
            except json.JSONDecodeError:
                admin = {
                    "username": "admin",
                    "password": hashlib.md5("admin123".encode()).hexdigest(),
                    "role": "admin"
                }
                with open(self.users_file, 'w') as f:
                    json.dump([admin], f)

    def toggle_password(self, entry, button):
        if entry.cget("show") == "*":
            entry.configure(show="")
            button.configure(text="👁️")
        else:
            entry.configure(show="*")
            button.configure(text="👁️‍🗨️")

    def validate_input(self, entry, error_label, entry_type):
        value = entry.get().strip()
        if entry_type == "username":
            if len(value) < 3:
                error_label.configure(text="Tên đăng nhập phải có ít nhất 3 ký tự", foreground="#ff4444")
                return False
            error_label.configure(text="✓", foreground=self.accent_color)
            return True
        elif entry_type == "password":
            if len(value) < 6:
                error_label.configure(text="Mật khẩu phải có ít nhất 6 ký tự", foreground="#ff4444")
                return False
            error_label.configure(text="✓", foreground=self.accent_color)
            return True

    def create_login_screen(self):
        self.clear_window()
        
        # Tạo canvas cho nền gradient
        self.current_canvas = tk.Canvas(self.root, highlightthickness=0)
        self.current_canvas.pack(fill="both", expand=True)
        
        # Frame chính
        main_frame = ttk.Frame(self.current_canvas, padding=30, style="Main.TFrame")
        main_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.style.configure("Main.TFrame", background="white")
        
        # Khung form với viền nhẹ
        form_frame = tk.Frame(main_frame, bg="white", highlightbackground=self.border_color, highlightcolor=self.border_color, highlightthickness=2)
        form_frame.pack(pady=30, padx=30)
        
        # Logo
        ttk.Label(form_frame, 
                 text="📋 Đăng Nhập", 
                 font=("Segoe UI", 28, "bold"), 
                 foreground=self.primary_color,
                 background="white").pack(pady=(40, 20))
        
        # Frame chứa các trường nhập liệu
        input_frame = ttk.Frame(form_frame, style="Main.TFrame")
        input_frame.pack(pady=10)
        
        # Trường nhập liệu tên đăng nhập
        username_row = ttk.Frame(input_frame, style="Main.TFrame")
        username_row.grid(row=0, column=0, pady=5, padx=30, sticky="ew")
        username_icon = ttk.Label(username_row, text="👤", font=("Segoe UI", 16), background="white")
        username_icon.grid(row=0, column=0, padx=(0, 5))
        self.username_entry = ttk.Entry(username_row, width=30, style="Login.TEntry")
        self.username_entry.grid(row=0, column=1, padx=(0, 5))
        toggle_placeholder = ttk.Button(username_row, text="", width=0, style="SecondaryLogin.TButton", state="disabled")
        toggle_placeholder.grid(row=0, column=2, padx=(0, 15))
        self.username_entry_error = ttk.Label(username_row, text="", font=("Segoe UI", 10), foreground="#ff4444", background="white")
        self.username_entry_error.grid(row=1, column=1, pady=(2, 0), sticky="w")
        self.username_entry.bind("<KeyRelease>", lambda e: self.validate_input(self.username_entry, self.username_entry_error, "username"))
        
        # Trường nhập liệu mật khẩu
        password_row = ttk.Frame(input_frame, style="Main.TFrame")
        password_row.grid(row=1, column=0, pady=5, padx=30, sticky="ew")
        password_icon = ttk.Label(password_row, text="🔒", font=("Segoe UI", 16), background="white")
        password_icon.grid(row=0, column=0, padx=(0, 5))
        self.password_entry = ttk.Entry(password_row, show="*", width=30, style="Login.TEntry")
        self.password_entry.grid(row=0, column=1, padx=(0, 5))
        toggle_btn = ttk.Button(password_row, 
                               text="👁️‍🗨️", 
                               width=4, 
                               style="SecondaryLogin.TButton",
                               command=lambda: self.toggle_password(self.password_entry, toggle_btn))
        toggle_btn.grid(row=0, column=2, padx=(0, 15))
        self.password_entry_error = ttk.Label(password_row, text="", font=("Segoe UI", 10), foreground="#ff4444", background="white")
        self.password_entry_error.grid(row=1, column=1, pady=(2, 0), sticky="w")
        self.password_entry.bind("<KeyRelease>", lambda e: self.validate_input(self.password_entry, self.password_entry_error, "password"))
        
        # Nút đăng nhập
        ttk.Button(form_frame, 
                  text="Đăng Nhập", 
                  command=self.login, 
                  style="Login.TButton").pack(fill="x", padx=30, pady=(20, 10))
        
        # Nút đăng ký
        ttk.Button(form_frame, 
                  text="Tạo tài khoản mới", 
                  command=self.create_register_screen, 
                  style="SecondaryLogin.TButton").pack(pady=10)
        
        # Thanh trạng thái
        status_bar = ttk.Label(self.root, 
                              text="Đăng nhập với 'admin'/'admin123' để vào với vai trò quản trị viên.", 
                              anchor="center", 
                              background="white", 
                              foreground=self.secondary_color, 
                              font=("Segoe UI", 10), 
                              padding=10)
        status_bar.pack(side="bottom", fill="x")

    def create_register_screen(self):
        self.clear_window()
        
        # Tạo canvas cho nền gradient
        self.current_canvas = tk.Canvas(self.root, highlightthickness=0)
        self.current_canvas.pack(fill="both", expand=True)
        
        # Frame chính
        main_frame = ttk.Frame(self.current_canvas, padding=30, style="Main.TFrame")
        main_frame.place(relx=0.5, rely=0.5, anchor="center")
        self.style.configure("Main.TFrame", background="white")
        
        # Khung form với viền nhẹ
        form_frame = tk.Frame(main_frame, bg="white", highlightbackground=self.border_color, highlightcolor=self.border_color, highlightthickness=2)
        form_frame.pack(pady=30, padx=30)
        
        # Logo
        ttk.Label(form_frame, 
                 text="📋 Đăng Ký", 
                 font=("Segoe UI", 28, "bold"), 
                 foreground=self.primary_color,
                 background="white").pack(pady=(40, 20))
        
        # Frame chứa các trường nhập liệu
        input_frame = ttk.Frame(form_frame, style="Main.TFrame")
        input_frame.pack(pady=10)
        
        # Trường nhập liệu tên đăng nhập
        username_row = ttk.Frame(input_frame, style="Main.TFrame")
        username_row.grid(row=0, column=0, pady=5, padx=30, sticky="ew")
        username_icon = ttk.Label(username_row, text="👤", font=("Segoe UI", 16), background="white")
        username_icon.grid(row=0, column=0, padx=(0, 5))
        self.reg_username_entry = ttk.Entry(username_row, width=30, style="Login.TEntry")
        self.reg_username_entry.grid(row=0, column=1, padx=(0, 5))
        toggle_placeholder = ttk.Button(username_row, text="", width=0, style="SecondaryLogin.TButton", state="disabled")
        toggle_placeholder.grid(row=0, column=2, padx=(0, 15))
        self.reg_username_entry_error = ttk.Label(username_row, text="", font=("Segoe UI", 10), foreground="#ff4444", background="white")
        self.reg_username_entry_error.grid(row=1, column=1, pady=(2, 0), sticky="w")
        self.reg_username_entry.bind("<KeyRelease>", lambda e: self.validate_input(self.reg_username_entry, self.reg_username_entry_error, "username"))
        
        # Trường nhập liệu mật khẩu
        password_row = ttk.Frame(input_frame, style="Main.TFrame")
        password_row.grid(row=1, column=0, pady=5, padx=30, sticky="ew")
        password_icon = ttk.Label(password_row, text="🔒", font=("Segoe UI", 16), background="white")
        password_icon.grid(row=0, column=0, padx=(0, 5))
        self.reg_password_entry = ttk.Entry(password_row, show="*", width=30, style="Login.TEntry")
        self.reg_password_entry.grid(row=0, column=1, padx=(0, 5))
        toggle_btn = ttk.Button(password_row, 
                               text="👁️‍🗨️", 
                               width=4, 
                               style="SecondaryLogin.TButton",
                               command=lambda: self.toggle_password(self.reg_password_entry, toggle_btn))
        toggle_btn.grid(row=0, column=2, padx=(0, 15))
        self.reg_password_entry_error = ttk.Label(password_row, text="", font=("Segoe UI", 10), foreground="#ff4444", background="white")
        self.reg_password_entry_error.grid(row=1, column=1, pady=(2, 0), sticky="w")
        self.reg_password_entry.bind("<KeyRelease>", lambda e: self.validate_input(self.reg_password_entry, self.reg_password_entry_error, "password"))
        
        # Nút đăng ký
        ttk.Button(form_frame, 
                  text="Đăng Ký", 
                  command=self.register, 
                  style="Login.TButton").pack(fill="x", padx=30, pady=(20, 10))
        
        # Nút quay lại
        ttk.Button(form_frame, 
                  text="Đã có tài khoản? Đăng nhập", 
                  command=self.create_login_screen, 
                  style="SecondaryLogin.TButton").pack(pady=10)
        
        # Thanh trạng thái
        status_bar = ttk.Label(self.root, 
                              text="Tài khoản mới sẽ được đăng ký với vai trò người dùng.", 
                              anchor="center", 
                              background="white", 
                              foreground=self.secondary_color, 
                              font=("Segoe UI", 10), 
                              padding=10)
        status_bar.pack(side="bottom", fill="x")

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        self.username_entry_error.configure(text="")
        self.password_entry_error.configure(text="")
        
        if not username or not password:
            if not username:
                self.username_entry_error.configure(text="Vui lòng nhập tên đăng nhập")
            if not password:
                self.password_entry_error.configure(text="Vui lòng nhập mật khẩu")
            return
            
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File users.json bị lỗi, khởi tạo lại.")
            self.initialize_files()
            users = [{"username": "admin", "password": hashlib.md5("admin123".encode()).hexdigest(), "email": "admin@example.com", "role": "admin"}]
            
        for user in users:
            if user['username'] == username and user['password'] == hashlib.md5(password.encode()).hexdigest():
                self.current_user = username
                self.user_role = user['role']
                messagebox.showinfo("Thành công", f"Đăng nhập thành công với vai trò: {self.user_role}")
                self.create_main_screen()
                return
                
        self.password_entry_error.configure(text="Tên đăng nhập hoặc mật khẩu không đúng")

    def register(self):
        username = self.reg_username_entry.get().strip()
        password = self.reg_password_entry.get()
        
        self.reg_username_entry_error.configure(text="")
        self.reg_password_entry_error.configure(text="")
        
        if not username or not password:
            if not username:
                self.reg_username_entry_error.configure(text="Vui lòng nhập tên đăng nhập")
            if not password:
                self.reg_password_entry_error.configure(text="Vui lòng nhập mật khẩu")
            return
            
        if len(password) < 6:
            self.reg_password_entry_error.configure(text="Mật khẩu phải có ít nhất 6 ký tự")
            return
            
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except json.JSONDecodeError:
            users = [{"username": "admin", "password": hashlib.md5("admin123".encode()).hexdigest(), "email": "admin@example.com", "role": "admin"}]
            
        for user in users:
            if user['username'] == username:
                self.reg_username_entry_error.configure(text="Tên đăng nhập đã tồn tại")
                return
                
        new_user = {
            "username": username,
            "password": hashlib.md5(password.encode()).hexdigest(),
            "email": f"{username}@gmail.com",
            "role": "user"
        }
        
        users.append(new_user)
        with open(self.users_file, 'w') as f:
            json.dump(users, f, indent=2)
            
        messagebox.showinfo("Thành công", "Đăng ký thành công với vai trò người dùng!")
        self.create_login_screen()

    def logout(self):
        if messagebox.askyesno("Xác nhận", "Bạn có chắc muốn đăng xuất?"):
            self.current_user = None
            self.user_role = None
            self.clear_entries()
            self.create_login_screen()
            messagebox.showinfo("Thành công", "Đã đăng xuất thành công!")
            self.cleanup()

    def create_main_screen(self):
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding=20, style="Main.TFrame")
        main_frame.pack(expand=True, fill="both")
        
        ttk.Label(main_frame, text="📋 Danh Bạ", font=("Segoe UI", 24, "bold"), foreground=self.text_color).pack(pady=20)
        
        input_frame = ttk.LabelFrame(main_frame, text="Thông tin liên hệ", padding=15)
        input_frame.pack(fill="x", pady=10, padx=20)
        
        content_frame = ttk.Frame(input_frame)
        content_frame.pack(fill="x", padx=10, pady=10)
        
        image_frame = ttk.Frame(content_frame)
        image_frame.pack(side="left", padx=10)
        if self.default_image:
            image_label = tk.Label(image_frame, image=self.default_image, background=self.bg_color)
            image_label.pack()
        else:
            placeholder = tk.Canvas(image_frame, width=80, height=80, bg="#bdc3c7", highlightthickness=0)
            placeholder.create_oval(5, 5, 75, 75, fill="#95a5a6")
            placeholder.pack()
            ttk.Label(image_frame, text="No image", font=("Segoe UI", 8)).pack()
        
        fields_frame = ttk.Frame(content_frame)
        fields_frame.pack(side="left", fill="x", expand=True)
        
        ttk.Label(fields_frame, text="Họ tên:").grid(row=0, column=0, padx=10, pady=10, sticky="e")
        self.name_entry = ttk.Entry(fields_frame, width=40)
        self.name_entry.grid(row=0, column=1, padx=10, pady=10, sticky="ew")
        fields_frame.grid_columnconfigure(1, weight=1)
        
        ttk.Label(fields_frame, text="Số điện thoại:").grid(row=1, column=0, padx=10, pady=10, sticky="e")
        self.phone_entry = ttk.Entry(fields_frame, width=40)
        self.phone_entry.grid(row=1, column=1, padx=10, pady=10, sticky="ew")
        
        ttk.Label(fields_frame, text="Email:").grid(row=2, column=0, padx=10, pady=10, sticky="e")
        self.email_entry = ttk.Entry(fields_frame, width=40)
        self.email_entry.grid(row=2, column=1, padx=10, pady=10, sticky="ew")
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=15)
        
        ttk.Button(btn_frame, text="Thêm", command=self.add_contact).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Cập nhật", command=self.update_contact).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Xóa", command=self.delete_contact, style="Secondary.TButton").pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Crawl dữ liệu", command=self.crawl_data).pack(side="left", padx=10)
        
        if self.user_role == "admin":
            ttk.Button(btn_frame, text="Quản lý người dùng", command=self.create_user_management_screen, style="Admin.TButton").pack(side="left", padx=10)
        
        ttk.Button(btn_frame, text="Đăng xuất", command=self.logout, style="Logout.TButton").pack(side="left", padx=10)
        
        tree_frame = ttk.LabelFrame(main_frame, text="Danh sách liên hệ", padding=10)
        tree_frame.pack(fill="both", expand=True, pady=10, padx=20)
        
        self.tree = ttk.Treeview(tree_frame, columns=("Name", "Phone", "Email"), show="headings", height=12)
        self.tree.heading("Name", text="Họ tên")
        self.tree.heading("Phone", text="Số điện thoại")
        self.tree.heading("Email", text="Email")
        self.tree.column("Name", width=200, stretch=True)
        self.tree.column("Phone", width=150, stretch=True)
        self.tree.column("Email", width=250, stretch=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        self.tree.bind('<<TreeviewSelect>>', self.on_tree_select)
        
        self.load_contacts()
        
        status_bar = ttk.Label(self.root, text=f"Đăng nhập với: {self.current_user} ({self.user_role}) | {'Tất cả quyền' if self.user_role == 'admin' else 'Quyền giới hạn'}", relief="sunken", anchor="w", background="#bdc3c7", padding=5)
        status_bar.pack(side="bottom", fill="x")

    def create_user_management_screen(self):
        if self.user_role != "admin":
            messagebox.showerror("Lỗi", "Chỉ admin mới có quyền truy cập!")
            return
            
        self.clear_window()
        
        main_frame = ttk.Frame(self.root, padding=20, style="Main.TFrame")
        main_frame.pack(expand=True, fill="both")
        
        ttk.Label(main_frame, text="👤 Quản Lý Người Dùng", font=("Segoe UI", 24, "bold"), foreground=self.text_color).pack(pady=20)
        
        tree_frame = ttk.LabelFrame(main_frame, text="Danh sách người dùng", padding=10)
        tree_frame.pack(fill="both", expand=True, pady=10, padx=20)
        
        self.user_tree = ttk.Treeview(tree_frame, columns=("Username", "Role"), show="headings", height=12)
        self.user_tree.heading("Username", text="Tên đăng nhập")
        self.user_tree.heading("Role", text="Vai trò")
        self.user_tree.column("Username", width=200, stretch=True)
        self.user_tree.column("Role", width=150, stretch=True)
        
        scrollbar = ttk.Scrollbar(tree_frame, orient="vertical", command=self.user_tree.yview)
        self.user_tree.configure(yscrollcommand=scrollbar.set)
        self.user_tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(pady=15)
        ttk.Button(btn_frame, text="Xóa người dùng", command=self.delete_user, style="Secondary.TButton").pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Quay lại", command=self.create_main_screen).pack(side="left", padx=10)
        ttk.Button(btn_frame, text="Đăng xuất", command=self.logout, style="Logout.TButton").pack(side="left", padx=10)
        
        self.load_users()
        
        status_bar = ttk.Label(self.root, text=f"Quản lý người dùng (Admin: {self.current_user})", relief="sunken", anchor="w", background="#bdc3c7", padding=5)
        status_bar.pack(side="bottom", fill="x")

    def load_users(self):
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
            
        try:
            with open(self.users_file, 'r') as f:
                users = json.load(f)
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File users.json bị lỗi, khởi tạo lại.")
            self.initialize_files()
            return
            
        for user in users:
            self.user_tree.insert("", tk.END, values=(user['username'], user['role']))

    def delete_user(self):
        selected_item = self.user_tree.selection()
        if not selected_item:
            messagebox.showerror("Lỗi", "Vui lòng chọn người dùng để xóa!")
            return
            
        username = self.user_tree.item(selected_item)['values'][0]
        
        if username == "admin":
            messagebox.showerror("Lỗi", "Không thể xóa tài khoản admin!")
            return
            
        if messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa người dùng {username}?"):
            try:
                with open(self.users_file, 'r') as f:
                    users = json.load(f)
                
                users = [user for user in users if user['username'] != username]
                
                with open(self.users_file, 'w') as f:
                    json.dump(users, f, indent=2)
                
                self.load_users()
                messagebox.showinfo("Thành công", "Xóa người dùng thành công!")
            except json.JSONDecodeError:
                messagebox.showerror("Lỗi", "File users.json bị lỗi, khởi tạo lại.")
                self.initialize_files()

    def clear_window(self):
        for widget in self.root.winfo_children():
            widget.destroy()

    def load_contacts(self):
        for item in self.tree.get_children():
            self.tree.delete(item)
            
        try:
            with open(self.contacts_file, 'r') as f:
                contacts = json.load(f)
                
            if not isinstance(contacts, list):
                contacts = []
                with open(self.contacts_file, 'w') as f:
                    json.dump(contacts, f)
                    
            for contact in contacts:
                self.tree.insert("", tk.END, values=(contact['name'], contact['phone'], contact['email']))
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File contacts.json bị lỗi, khởi tạo lại.")
            with open(self.contacts_file, 'w') as f:
                json.dump([], f)

    def validate_email(self, email):
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def validate_phone(self, phone):
        pattern = r'^\+?\d{10,12}$'
        return re.match(pattern, phone) is not None

    def add_contact(self):
        name = self.name_entry.get().strip()
        phone = self.phone_entry.get().strip()
        email = self.email_entry.get().strip()
        
        if not name or not phone or not email:
            messagebox.showerror("Lỗi", "Vui lòng điền đầy đủ thông tin!")
            return
            
        if not self.validate_email(email):
            messagebox.showerror("Lỗi", "Email không đúng định dạng!")
            return
            
        if not self.validate_phone(phone):
            messagebox.showerror("Lỗi", "Số điện thoại không đúng định dạng (10-12 số)!")
            return
            
        try:
            with open(self.contacts_file, 'r') as f:
                contacts = json.load(f)
                
            if not isinstance(contacts, list):
                contacts = []
                
            for contact in contacts:
                if contact['name'].lower() == name.lower():
                    messagebox.showerror("Lỗi", "Tên liên hệ đã tồn tại!")
                    return
                if contact['email'].lower() == email.lower():
                    messagebox.showerror("Lỗi", "Email đã tồn tại!")
                    return
                
            contacts.append({
                "name": name,
                "phone": phone,
                "email": email,
                "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            })
            
            with open(self.contacts_file, 'w') as f:
                json.dump(contacts, f, indent=2)
                
            self.load_contacts()
            self.clear_entries()
            messagebox.showinfo("Thành công", "Thêm liên hệ thành công!")
            
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File contacts.json bị lỗi, khởi tạo lại.")
            with open(self.contacts_file, 'w') as f:
                json.dump([], f)
            self.add_contact()

    def on_tree_select(self, event):
        selected_item = self.tree.selection()
        if selected_item:
            values = self.tree.item(selected_item)['values']
            self.name_entry.delete(0, tk.END)
            self.phone_entry.delete(0, tk.END)
            self.email_entry.delete(0, tk.END)
            
            self.name_entry.insert(0, values[0])
            self.phone_entry.insert(0, values[1])
            self.email_entry.insert(0, values[2])

    def update_contact(self):
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Lỗi", "Vui lòng chọn liên hệ để cập nhật!")
            return
            
        name = self.name_entry.get().strip()
        phone = self.phone_entry.get().strip()
        email = self.email_entry.get().strip()
        
        if not name or not phone or not email:
            messagebox.showerror("Lỗi", "Vui lòng điền đầy đủ thông tin!")
            return
            
        if not self.validate_email(email):
            messagebox.showerror("Lỗi", "Email không đúng định dạng!")
            return
            
        if not self.validate_phone(phone):
            messagebox.showerror("Lỗi", "Số điện thoại không đúng định dạng (10-12 số)!")
            return
            
        try:
            with open(self.contacts_file, 'r') as f:
                contacts = json.load(f)
                
            if not isinstance(contacts, list):
                contacts = []
                
            old_name = self.tree.item(selected_item)['values'][0]
            for contact in contacts:
                if contact['name'] != old_name and contact['email'].lower() == email.lower():
                    messagebox.showerror("Lỗi", "Email đã tồn tại!")
                    return
                
            for contact in contacts:
                if contact['name'] == old_name:
                    contact['name'] = name
                    contact['phone'] = phone
                    contact['email'] = email
                    contact['updated_at'] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    break
                
            with open(self.contacts_file, 'w') as f:
                json.dump(contacts, f, indent=2)
                
            self.load_contacts()
            self.clear_entries()
            messagebox.showinfo("Thành công", "Cập nhật liên hệ thành công!")
            
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File contacts.json bị lỗi, khởi tạo lại.")
            with open(self.contacts_file, 'w') as f:
                json.dump([], f)

    def delete_contact(self):
        if self.user_role != "admin":
            messagebox.showerror("Lỗi", "Chỉ admin mới có quyền xóa!")
            return
            
        selected_item = self.tree.selection()
        if not selected_item:
            messagebox.showerror("Lỗi", "Vui lòng chọn liên hệ để xóa!")
            return
            
        name = self.tree.item(selected_item)['values'][0]
        
        if not messagebox.askyesno("Xác nhận", f"Bạn có chắc muốn xóa liên hệ {name}?"):
            return
            
        try:
            with open(self.contacts_file, 'r') as f:
                contacts = json.load(f)
                
            if not isinstance(contacts, list):
                contacts = []
                
            contacts = [contact for contact in contacts if contact['name'] != name]
            
            with open(self.contacts_file, 'w') as f:
                json.dump(contacts, f, indent=2)
                
            self.load_contacts()
            self.clear_entries()
            messagebox.showinfo("Thành công", "Xóa liên hệ thành công!")
            
        except json.JSONDecodeError:
            messagebox.showerror("Lỗi", "File contacts.json bị lỗi, khởi tạo lại.")
            with open(self.contacts_file, 'w') as f:
                json.dump([], f)

    def clear_entries(self):
        self.name_entry.delete(0, tk.END)
        self.phone_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)

    def crawl_data(self):
        try:
            # Danh sách tên tiếng Việt để ánh xạ
            vietnamese_last_names = ['Nguyễn', 'Trần', 'Lê', 'Phạm', 'Hoàng', 'Huỳnh', 'Vũ', 'Võ', 'Đặng', 'Bùi']
            vietnamese_first_names = ['Anh', 'Bình', 'Cường', 'Duy', 'Hà', 'Hải', 'Hùng', 'Lan', 'Linh', 'Mai']

            # Gọi API từ Random User API với tham số nat=vn để lấy dữ liệu người dùng từ Việt Nam
            url = "https://randomuser.me/api/?nat=vn&results=5"  # Lấy 5 người dùng
            response = requests.get(url, timeout=10)
            response.raise_for_status()  # Kiểm tra nếu có lỗi khi gọi API
            data = response.json()

            # Đọc dữ liệu hiện có từ file contacts.json
            try:
                with open(self.contacts_file, 'r') as f:
                    contacts = json.load(f)
                    
                if not isinstance(contacts, list):
                    contacts = []
                    
            except json.JSONDecodeError:
                contacts = []
                
            # Lấy danh sách email hiện có để tránh trùng lặp
            existing_emails = {contact['email'].lower() for contact in contacts}
            
            # Xử lý dữ liệu từ API
            for user in data['results']:
                # Ánh xạ tên thành tên tiếng Việt chuẩn
                last_name = random.choice(vietnamese_last_names)
                first_name = random.choice(vietnamese_first_names)
                full_name = f"{last_name} {first_name}"
                
                # Xử lý số điện thoại
                phone = user['phone'].replace("-", "")  # Xóa dấu gạch ngang trong số điện thoại
                if not phone.startswith("+84"):
                    phone = "+84" + phone[1:] if phone.startswith("0") else "+84" + phone

                # Tạo username và email mang phong cách tiếng Việt
                username = f"{last_name.lower()}_{first_name.lower()}{random.randint(1990, 2025)}"
                email = f"{username}@gmail.com"
                
                # Kiểm tra email trùng lặp
                if email.lower() not in existing_emails:
                    contacts.append({
                        "name": full_name,
                        "phone": phone,
                        "email": email,
                        "created_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    })
                    existing_emails.add(email.lower())
                
            # Lưu dữ liệu vào file contacts.json
            with open(self.contacts_file, 'w') as f:
                json.dump(contacts, f, indent=2)
                
            self.load_contacts()
            messagebox.showinfo("Thành công", "Lấy dữ liệu từ API thành công và lưu vào file contacts.json!")
            
        except requests.exceptions.RequestException as e:
            messagebox.showerror("Lỗi", f"Không thể lấy dữ liệu từ API: {str(e)}")
        except Exception as e:
            messagebox.showerror("Lỗi", f"Lỗi khi xử lý dữ liệu: {str(e)}")

if __name__ == "__main__":
    root = tk.Tk()
    app = ContactManagerApp(root)
    root.protocol("WM_DELETE_WINDOW", lambda: [app.cleanup(), root.destroy()])
    root.mainloop()