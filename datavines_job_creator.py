import tkinter as tk
from tkinter import ttk, filedialog, scrolledtext, messagebox
import threading
import json
import re
import uuid
import requests
import os
import sys


class DatavinesUI:
    def __init__(self, root):
        self.root = root
        root.title("DataVines数据质量规则配置工具")
        root.geometry("1100x1000")

        # 获取程序运行目录 - 支持打包为exe后的路径
        self.app_dir = os.path.dirname(os.path.abspath(sys.argv[0]))

        # 变量定义 - 设置默认文件路径
        default_sql = resource_path("default_ddl.sql")
        default_dict = resource_path("all_dictionaries.json")
        default_relations = resource_path("field_dict_relations.json")

        self.sql_file_path = tk.StringVar(
            value=default_sql if os.path.exists(default_sql) else ""
        )
        self.api_url = tk.StringVar(value="http://192.168.81.128:5600/api/v1")
        self.data_source_id = tk.IntVar(value=2)
        self.database_name = tk.StringVar(value="sfb_gj_test")
        self.log_file = tk.StringVar(
            value=os.path.join(self.app_dir, "datavines_jobs_created.log")
        )
        self.auth_token = tk.StringVar(
            value="eyJhbGciOiJIUzI1NiIsInppcCI6IkRFRiJ9.eNqqVkouUbIyNDcxNDE0Nzc0NDA21lEqLk1SslJKTMnNzFPSUSrNQ-YUADmGRsYmpmZAXmoFkGtoYWZubmZmbGlZCwAAAP__.XGGsrRWpNKywxClKyzy7WNJkDAv8Ayn56vMFAl1eI6U"
        )
        self.clear_existing_rules = tk.BooleanVar(value=False)

        # 代码字典表和字段代码集关系表变量
        self.code_dict_file = tk.StringVar(
            value=default_dict if os.path.exists(default_dict) else ""
        )
        self.field_dict_relation_file = tk.StringVar(
            value=default_relations if os.path.exists(default_relations) else ""
        )
        self.code_dicts = []  # 存储代码字典
        self.field_dict_relations = []  # 存储字段与代码集的关系

        # 创建UI组件
        self.create_widgets()

        # 数据存储
        self.tables = []
        self.selected_tables = []
        self.selected_rules = {"空值检查": True, "长度检查": True, "枚举值检查": True}

        # 如果有默认文件，则加载它们
        if os.path.exists(default_sql):
            self.log(f"使用默认SQL文件: {default_sql}")

        if os.path.exists(default_dict):
            self.load_code_dict_file(default_dict)

        if os.path.exists(default_relations):
            self.load_field_relation_file(default_relations)

        # 自动解析表结构
        # 使用after方法延迟执行，确保界面已完全加载
        if os.path.exists(default_sql):
            self.root.after(500, self.parse_sql)

    def create_widgets(self):
        # 创建主框架
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # 配置框架
        config_frame = ttk.LabelFrame(main_frame, text="配置", padding="10")
        config_frame.pack(fill=tk.X, pady=5)

        # SQL文件选择
        ttk.Label(config_frame, text="SQL文件:").grid(
            row=0, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.sql_file_path, width=50).grid(
            row=0, column=1, sticky=tk.W + tk.E, padx=5
        )
        ttk.Button(config_frame, text="浏览", command=self.browse_file).grid(
            row=0, column=2, sticky=tk.W
        )
        # 提示按钮
        ttk.Button(
            config_frame,
            text="?",
            width=2,
            command=lambda: messagebox.showinfo(
                "SQL格式说明",
                "目前需使用 VScode 的 Prettier SQL VSCode 插件来格式化",
            ),
        ).grid(row=0, column=3, sticky=tk.W)

        # DataVines API配置
        ttk.Label(config_frame, text="API地址:").grid(
            row=1, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.api_url, width=50).grid(
            row=1, column=1, sticky=tk.W + tk.E, padx=5
        )
        # 提示按钮
        ttk.Button(
            config_frame,
            text="?",
            width=2,
            command=lambda: messagebox.showinfo(
                "API地址",
                "以http://或https://开头，以/api/v1结尾",
            ),
        ).grid(row=1, column=2, sticky=tk.W)

        ttk.Label(config_frame, text="认证令牌:").grid(
            row=2, column=0, sticky=tk.W, pady=5
        )
        auth_entry = ttk.Entry(config_frame, textvariable=self.auth_token, width=50)
        auth_entry.grid(row=2, column=1, sticky=tk.W + tk.E, padx=5)
        # 提示按钮
        ttk.Button(
            config_frame,
            text="?",
            width=2,
            command=lambda: messagebox.showinfo(
                "认证说明",
                "请输入DataVines API的认证令牌，可以在【令牌管理】创建获取，也可以在F12开发者工具中获取请求头中的Authorization",
            ),
        ).grid(row=2, column=2, sticky=tk.W)

        ttk.Label(config_frame, text="数据源ID:").grid(
            row=3, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.data_source_id, width=10).grid(
            row=3, column=1, sticky=tk.W, padx=5
        )

        ttk.Label(config_frame, text="数据库名:").grid(
            row=4, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.database_name, width=30).grid(
            row=4, column=1, sticky=tk.W, padx=5
        )

        ttk.Label(config_frame, text="日志文件:").grid(
            row=5, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.log_file, width=50).grid(
            row=5, column=1, sticky=tk.W, padx=5
        )

        # 代码字典表文件选择
        ttk.Label(config_frame, text="代码字典表:").grid(
            row=6, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(config_frame, textvariable=self.code_dict_file, width=50).grid(
            row=6, column=1, sticky=tk.W + tk.E, padx=5
        )
        ttk.Button(config_frame, text="浏览", command=self.browse_code_dict_file).grid(
            row=6, column=2, sticky=tk.W
        )
        # 提示按钮
        ttk.Button(
            config_frame,
            text="?",
            width=2,
            command=lambda: messagebox.showinfo(
                "示例",
                """[{
    "dict_id": "1",
    "dict_name": "性别",
    "codes": [
        {"code": "M", "name": "男"},
        {"code": "F", "name": "女"}
    ]
}]""",
            ),
        ).grid(row=6, column=3, sticky=tk.W)

        # 字段代码集关系表文件选择
        ttk.Label(config_frame, text="字段代码集关系:").grid(
            row=7, column=0, sticky=tk.W, pady=5
        )
        ttk.Entry(
            config_frame, textvariable=self.field_dict_relation_file, width=50
        ).grid(row=7, column=1, sticky=tk.W + tk.E, padx=5)
        ttk.Button(
            config_frame, text="浏览", command=self.browse_field_relation_file
        ).grid(row=7, column=2, sticky=tk.W)
        # 提示按钮
        ttk.Button(
            config_frame,
            text="?",
            width=2,
            command=lambda: messagebox.showinfo(
                "示例",
                """[{
    "table_name": "Z2010",
    "colmun_name": "Z201010",
    "dict_id": "CZ001"
}]""",
            ),
        ).grid(row=7, column=3, sticky=tk.W)

        # 解析按钮 (修改行号)
        ttk.Button(config_frame, text="解析表结构", command=self.parse_sql).grid(
            row=8, column=0, pady=10
        )
        ttk.Button(config_frame, text="测试连接", command=self.test_connection).grid(
            row=8, column=1, pady=10, sticky=tk.W
        )

        # 规则选择框架
        rule_frame = ttk.LabelFrame(main_frame, text="选择要配置的规则", padding="10")
        rule_frame.pack(fill=tk.X, pady=5)

        # 规则复选框
        self.null_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(rule_frame, text="空值检查", variable=self.null_var).grid(
            row=0, column=0, padx=10
        )

        self.length_check_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            rule_frame, text="长度检查", variable=self.length_check_var
        ).grid(row=0, column=1, padx=10)

        self.enum_check_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            rule_frame, text="枚举值检查", variable=self.enum_check_var
        ).grid(row=0, column=2, padx=10)

        ttk.Checkbutton(
            rule_frame, text="清空现有规则", variable=self.clear_existing_rules
        ).grid(row=0, column=3, padx=10)

        # 表格选择框架
        table_frame = ttk.LabelFrame(main_frame, text="选择要配置的表", padding="10")
        table_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        # 创建表格和滚动条容器
        tree_container = ttk.Frame(table_frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        # 表选择框
        self.table_tree = ttk.Treeview(
            tree_container,
            columns=("name", "comment", "columns"),
            show="headings",
            height=10,
        )
        self.table_tree.heading("name", text="表名")
        self.table_tree.heading("comment", text="注释")
        self.table_tree.heading("columns", text="字段数")
        self.table_tree.column("name", width=150)
        self.table_tree.column("comment", width=250)
        self.table_tree.column("columns", width=100)
        self.table_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 表格双击事件绑定
        self.table_tree.bind("<Double-1>", self.show_table_columns)

        # 滚动条
        table_scroll = ttk.Scrollbar(
            tree_container, orient="vertical", command=self.table_tree.yview
        )
        table_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.table_tree.configure(yscrollcommand=table_scroll.set)

        # 按钮框架
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=10)

        ttk.Button(btn_frame, text="选择全部", command=self.select_all_tables).pack(
            side=tk.LEFT, padx=5
        )
        ttk.Button(btn_frame, text="取消选择", command=self.unselect_all_tables).pack(
            side=tk.LEFT, padx=5
        )
        # 保存代码集关系按钮到主界面
        ttk.Button(btn_frame, text="生成规则", command=self.generate_rules).pack(
            side=tk.RIGHT, padx=5
        )
        ttk.Button(
            btn_frame, text="保存代码集关系", command=self.save_field_dict_relations
        ).pack(side=tk.RIGHT, padx=5)

        # 日志框架
        log_frame = ttk.LabelFrame(main_frame, text="执行日志", padding="10")
        log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 状态栏
        self.status_var = tk.StringVar()
        ttk.Label(
            self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W
        ).pack(fill=tk.X, side=tk.BOTTOM)
        self.status_var.set("准备就绪")

        # 设置窗口位置居中
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def browse_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("SQL Files", "*.sql"), ("All Files", "*.*")]
        )
        if filepath:
            self.sql_file_path.set(filepath)
            self.log("已选择SQL文件: " + filepath)

            # 如果选择了非默认文件，给出提示
            default_sql = resource_path("default_ddl.sql")
            if filepath != default_sql and os.path.exists(default_sql):
                self.log("注意: 您选择了非默认SQL文件，默认文件为: " + default_sql)

    def log(self, message):
        self.log_text.insert(tk.END, message + "\n")
        self.log_text.see(tk.END)

    def get_auth_headers(self):
        """获取包含认证信息的请求头"""
        headers = {"Content-Type": "application/json"}
        auth_token = self.auth_token.get().strip()
        if auth_token:
            # 检查是否已包含Bearer前缀
            if not auth_token.lower().startswith("bearer "):
                auth_token = "Bearer " + auth_token
            headers["Authorization"] = auth_token
        return headers

    def test_connection(self):
        """测试DataVines API连接"""
        api_url = self.api_url.get().rstrip("/")

        try:
            # 使用/api/v1/workspace/list接口测试连接
            test_url = f"{api_url}/workspace/list"

            self.log(f"测试连接: {test_url}")
            response = requests.get(
                test_url, headers=self.get_auth_headers(), verify=False
            )

            if response.status_code == 200:
                messagebox.showinfo("连接成功", "成功连接到DataVines API!")
                self.log(f"连接成功! 返回数据: {response.json()}")
            elif response.status_code == 401:
                messagebox.showerror("认证失败", "认证令牌无效或已过期")
                self.log(f"认证失败: {response.text}")
            else:
                messagebox.showerror("连接失败", f"状态码: {response.status_code}")
                self.log(f"连接失败! 错误信息: {response.text}")
        except Exception as e:
            messagebox.showerror("连接错误", str(e))
            self.log(f"连接错误: {str(e)}")

    def parse_sql(self):
        sql_path = self.sql_file_path.get()
        if not sql_path or not os.path.exists(sql_path):
            messagebox.showerror("错误", "请选择有效的SQL文件")
            return

        self.log("正在解析SQL文件...")
        self.status_var.set("解析中...")

        # 使用线程避免UI冻结
        def parse_task():
            try:
                # 直接使用改进的 parse_sql 函数
                parsed_tables = parse_sql(sql_path)

                # 将解析结果转换为UI程序需要的格式
                self.tables = []
                for table_name, table_info in parsed_tables.items():
                    columns = []
                    # 跳过表注释特殊键
                    for column_name, column_info in table_info.items():
                        if column_name != "__table_comment__":
                            # 提取VARCHAR长度
                            max_length = None
                            data_type_upper = column_info["type"].upper()

                            # 处理 VARCHAR 类型
                            if "VARCHAR" in data_type_upper:
                                length_match = re.search(
                                    r"VARCHAR\s*\((\d+)\)", data_type_upper
                                )
                                if length_match:
                                    max_length = int(length_match.group(1))
                            # 处理 INT 类型
                            elif "INT" in data_type_upper:
                                length_match = re.search(
                                    r"INT\s*\((\d+)\)", data_type_upper
                                )
                                if length_match:
                                    max_length = int(length_match.group(1))
                            # 处理 DECIMAL 类型 (如 DECIMAL(10,2))
                            elif "DECIMAL" in data_type_upper:
                                length_match = re.search(
                                    r"DECIMAL\s*\((\d+),\s*\d+\)", data_type_upper
                                )
                                if length_match:
                                    max_length = int(length_match.group(1))
                            # 处理其他可能有长度的类型
                            else:
                                # 通用匹配模式，适用于各种类型后面跟长度参数的情况
                                length_match = re.search(
                                    r"\w+\s*\((\d+)\)", data_type_upper
                                )
                                if length_match:
                                    max_length = int(length_match.group(1))

                            # 检查是否为枚举类型字段
                            is_enum_field = False
                            dict_id = None
                            dict_name = ""
                            multi_select = False
                            separator = "^"

                            if self.field_dict_relations:
                                for relation in self.field_dict_relations:
                                    if (
                                        relation.get("table_name", "").upper()
                                        == table_name.upper()
                                        and relation.get("colmun_name", "").upper()
                                        == column_name.upper()
                                    ):
                                        dict_id = relation.get("dict_id")
                                        is_enum_field = True
                                        multi_select = relation.get(
                                            "multi_select", False
                                        )
                                        separator = relation.get("separator", "^")
                                        # 找到代码集名称
                                        for code_dict in self.code_dicts:
                                            if code_dict.get("dict_id") == dict_id:
                                                dict_name = code_dict.get(
                                                    "dict_name", ""
                                                )
                                                break
                                        break

                            columns.append(
                                {
                                    "name": column_name,
                                    "type": column_info["type"],
                                    "not_null": column_info["required"],
                                    "comment": column_info["comment"],
                                    "max_length": max_length,
                                    "is_enum": is_enum_field,
                                    "dict_id": dict_id,
                                    "dict_name": dict_name,
                                    "multi_select": multi_select,
                                    "separator": separator,
                                }
                            )

                    # 获取表注释
                    table_comment = table_info.get("__table_comment__", "")

                    # 只添加有字段的表
                    if columns:
                        self.tables.append(
                            {
                                "name": table_name,
                                "comment": table_comment,
                                "columns": columns,
                            }
                        )

                self.root.after(0, self.update_table_list)
            except Exception as e:
                import traceback

                error_msg = traceback.format_exc()
                self.root.after(0, lambda: self.log(f"解析错误: {str(e)}\n{error_msg}"))
                self.root.after(0, lambda: self.status_var.set("解析失败"))

        threading.Thread(target=parse_task).start()

    def update_table_list(self):
        # 清空表格
        for item in self.table_tree.get_children():
            self.table_tree.delete(item)

        # 添加表格数据
        for table in self.tables:
            self.table_tree.insert(
                "",
                tk.END,
                values=(table["name"], table["comment"], len(table["columns"])),
            )

        self.log(f"成功解析 {len(self.tables)} 个表结构")
        self.status_var.set(f"已加载 {len(self.tables)} 个表")

    def select_all_tables(self):
        for item in self.table_tree.get_children():
            self.table_tree.selection_add(item)

    def unselect_all_tables(self):
        for item in self.table_tree.get_children():
            self.table_tree.selection_remove(item)

    # 双击表格行显示字段详情
    def show_table_columns(self, event):
        """双击表格行显示该表的字段详情"""
        # 获取双击的项目
        selected_item = self.table_tree.selection()
        if not selected_item:
            return

        # 获取选中的表名
        table_name = self.table_tree.item(selected_item[0])["values"][0]

        # 查找表信息
        table_info = None
        for table in self.tables:
            if table["name"] == table_name:
                table_info = table
                break

        if not table_info:
            return

        # 创建新窗口显示字段详情
        column_window = tk.Toplevel(self.root)
        column_window.title(f"表 {table_name} 的字段详情")
        column_window.geometry("800x600")  # 扩大窗口以适应更多内容

        # 设置模态窗口
        column_window.transient(self.root)
        column_window.grab_set()

        # 创建容器框架
        frame = ttk.Frame(column_window, padding="10")
        frame.pack(fill=tk.BOTH, expand=True)

        # 表标题
        ttk.Label(frame, text=f"表名: {table_name}", font=("", 12, "bold")).pack(
            anchor=tk.W
        )
        ttk.Label(frame, text=f"注释: {table_info['comment']}").pack(
            anchor=tk.W, pady=(0, 10)
        )

        # 创建字段表格和滚动条容器
        tree_container = ttk.Frame(frame)
        tree_container.pack(fill=tk.BOTH, expand=True)

        # 创建字段表格 - 添加代码集列
        columns_tree = ttk.Treeview(
            tree_container,
            columns=("name", "type", "required", "comment", "dict"),
            show="headings",
            height=15,
        )
        columns_tree.heading("name", text="字段名")
        columns_tree.heading("type", text="类型长度")
        columns_tree.heading("required", text="必填")
        columns_tree.heading("comment", text="注释")
        columns_tree.heading("dict", text="代码集")
        columns_tree.column("name", width=150)
        columns_tree.column("type", width=120)
        columns_tree.column("required", width=60, anchor=tk.CENTER)
        columns_tree.column("comment", width=200)
        columns_tree.column("dict", width=200)
        columns_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # 滚动条
        col_scroll = ttk.Scrollbar(
            tree_container, orient="vertical", command=columns_tree.yview
        )
        col_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        columns_tree.configure(yscrollcommand=col_scroll.set)

        # 用于存储每个行的列信息，以便后续更新
        column_items = {}

        # 填充字段数据
        for i, column in enumerate(table_info["columns"]):
            # 显示代码集名称和ID（如果有）
            dict_display = (
                f"{column.get('dict_name', '')} ({column.get('dict_id', '')})"
                if column.get("dict_id")
                else ""
            )

            item_id = columns_tree.insert(
                "",
                tk.END,
                values=(
                    column["name"],
                    column["type"],
                    "是" if column["not_null"] else "否",
                    column["comment"],
                    dict_display,
                ),
            )

            # 保存每行对应的列对象，以便后续更新
            column_items[item_id] = i

        # 双击事件处理，用于编辑代码集
        def edit_dict_id(event):
            item = columns_tree.selection()[0]
            if item in column_items:
                column_index = column_items[item]
                column = table_info["columns"][column_index]

                # 只对枚举类型字段显示编辑窗口
                # if not column["is_enum"]:
                #     messagebox.showinfo("提示", "只能为枚举类型字段设置代码集")
                #     return

                # 创建代码集选择窗口
                dict_window = tk.Toplevel(column_window)
                dict_window.title(f"为字段 {column['name']} 设置代码集")
                dict_window.geometry("410x430")
                dict_window.transient(column_window)
                dict_window.grab_set()

                # 创建字典选择框架
                dict_frame = ttk.Frame(dict_window, padding="10")
                dict_frame.pack(fill=tk.BOTH, expand=True)

                ttk.Label(
                    dict_frame,
                    text=f"字段: {column['name']} ({column['comment']})",
                    font=("", 11),
                ).pack(anchor=tk.W, pady=(0, 10))

                # 如果没有代码字典，显示提示
                if not self.code_dicts:
                    ttk.Label(
                        dict_frame,
                        text="未加载代码字典，请先加载代码字典表文件",
                        foreground="red",
                    ).pack(pady=20)
                    ttk.Button(
                        dict_frame, text="确定", command=dict_window.destroy
                    ).pack(pady=10)
                    return

                # 创建代码集选择下拉框
                ttk.Label(dict_frame, text="选择代码集:").pack(
                    anchor=tk.W, pady=(10, 5)
                )

                # 准备下拉框选项
                dict_options = [("", "-- 不设置 --")]
                for dict_item in self.code_dicts:
                    dict_options.append(
                        (
                            dict_item.get("dict_id", ""),
                            f"{dict_item.get('dict_name', '')} ({dict_item.get('dict_id', '')})",
                        )
                    )

                # 创建下拉框
                dict_combobox = ttk.Combobox(
                    dict_frame,
                    width=40,
                    state="readonly",
                    values=[item[1] for item in dict_options],
                )

                # 设置当前选中项
                current_dict_id = column.get("dict_id", "")
                found = False
                for i, (dict_id, _) in enumerate(dict_options):
                    if dict_id == current_dict_id:
                        dict_combobox.current(i)
                        found = True
                        break

                # 如果没有找到匹配项，则设置为"不设置"选项
                if not found and dict_options:
                    dict_combobox.current(0)

                dict_combobox.pack(anchor=tk.W, pady=(0, 10), fill=tk.X)

                # 创建下拉框后添加多选选项
                multi_select_var = tk.BooleanVar(
                    value=column.get("multi_select", False)
                )
                separator_var = tk.StringVar(value=column.get("separator", "^"))

                # 多选选项框架
                multi_frame = ttk.Frame(dict_frame)
                multi_frame.pack(fill=tk.X, pady=(0, 0))

                # 在创建预览区域之前，先创建一个容器来放置多选和分隔符相关控件
                selection_container = ttk.Frame(dict_frame)
                selection_container.pack(fill=tk.X, pady=(0, 5))

                # 多选复选框放在容器内
                multi_check = ttk.Checkbutton(
                    selection_container,
                    text="允许多选",
                    variable=multi_select_var,
                    command=lambda: show_hide_separator(),
                )
                multi_check.pack(anchor=tk.W)

                # 分隔符框架也放在同一个容器内，紧跟多选框之后
                separator_frame = ttk.Frame(selection_container)
                ttk.Label(separator_frame, text="分隔符:").pack(
                    side=tk.LEFT, padx=(0, 5)
                )
                ttk.Entry(separator_frame, textvariable=separator_var, width=5).pack(
                    side=tk.LEFT
                )
                ttk.Label(separator_frame, text="(默认为 ^ )").pack(
                    side=tk.LEFT, padx=5
                )

                # 控制分隔符框架显示/隐藏的函数
                def show_hide_separator():
                    if multi_select_var.get():
                        separator_frame.pack(fill=tk.X, pady=(2, 0))
                    else:
                        separator_frame.pack_forget()

                # 初始化显示状态
                show_hide_separator()

                # 创建代码预览区域
                preview_frame = ttk.LabelFrame(dict_frame, text="代码预览", padding="5")
                preview_frame.pack(fill=tk.BOTH, expand=True, pady=10)

                preview_text = scrolledtext.ScrolledText(
                    preview_frame, height=8, width=40
                )
                preview_text.pack(fill=tk.BOTH, expand=True)

                # 显示代码预览函数
                def show_preview(*args):
                    preview_text.delete(1.0, tk.END)

                    # 获取当前选择的代码集ID
                    selected_index = dict_combobox.current()
                    if selected_index < 0:
                        return

                    dict_id = dict_options[selected_index][0]
                    if not dict_id:  # 如果选择了"不设置"
                        return

                    # 查找对应的代码集
                    for dict_item in self.code_dicts:
                        if dict_item.get("dict_id") == dict_id:
                            codes = dict_item.get("codes", [])
                            for code_item in codes:
                                preview_text.insert(
                                    tk.END,
                                    f"{code_item.get('code', '')}: {code_item.get('name', '')}\n",
                                )
                            break

                # 替换trace绑定方式，改用直接的事件绑定
                def on_combobox_select(event):
                    show_preview()

                # 绑定ComboboxSelected事件
                dict_combobox.bind("<<ComboboxSelected>>", on_combobox_select)

                # 初始显示预览(如果有初始选择)
                if dict_combobox.current() >= 0:
                    show_preview()

                # 确定按钮动作
                def apply_dict_id():
                    selected_index = dict_combobox.current()
                    if selected_index >= 0:
                        new_dict_id = dict_options[selected_index][0]  # 获取字典ID

                        # 获取多选和分隔符设置
                        is_multi_select = multi_select_var.get()
                        separator = separator_var.get() or "^"  # 默认分隔符为^

                        # 更新列信息
                        if new_dict_id:
                            # 查找字典名称
                            dict_name = ""
                            for dict_item in self.code_dicts:
                                if dict_item.get("dict_id") == new_dict_id:
                                    dict_name = dict_item.get("dict_name", "")
                                    break

                            column["dict_id"] = new_dict_id
                            column["dict_name"] = dict_name
                            column["is_enum"] = True  # 设置为枚举字段
                            column["multi_select"] = is_multi_select  # 设置多选标识
                            column["separator"] = separator  # 设置分隔符

                            # 更新表格显示
                            dict_display = f"{dict_name} ({new_dict_id})"
                            columns_tree.item(
                                item,
                                values=(
                                    column["name"],
                                    column["type"],
                                    "是" if column["not_null"] else "否",
                                    column["comment"],
                                    dict_display,
                                ),
                            )

                            # 添加或更新关系表
                            self.update_field_dict_relation(
                                table_name,
                                column["name"],
                                new_dict_id,
                                is_multi_select,
                                separator,
                            )
                        else:
                            # 清除代码集ID和名称
                            column.pop("dict_id", None)
                            column.pop("dict_name", None)
                            column["is_enum"] = False  # 移除枚举字段标识
                            column.pop("multi_select", None)  # 移除多选标识
                            column.pop("separator", None)  # 移除分隔符

                            # 更新表格显示
                            columns_tree.item(
                                item,
                                values=(
                                    column["name"],
                                    column["type"],
                                    "是" if column["not_null"] else "否",
                                    column["comment"],
                                    "",
                                ),
                            )

                            # 从关系表中移除
                            self.remove_field_dict_relation(table_name, column["name"])

                    dict_window.destroy()

                # 创建按钮区域
                btn_frame = ttk.Frame(dict_frame)
                btn_frame.pack(fill=tk.X, pady=10)

                ttk.Button(btn_frame, text="应用", command=apply_dict_id).pack(
                    side=tk.RIGHT, padx=5
                )
                ttk.Button(btn_frame, text="取消", command=dict_window.destroy).pack(
                    side=tk.RIGHT, padx=5
                )

                # 设置窗口位置居中
                dict_window.update_idletasks()
                width = dict_window.winfo_width()
                height = dict_window.winfo_height()
                x = (dict_window.winfo_screenwidth() // 2) - (width // 2)
                y = (dict_window.winfo_screenheight() // 2) - (height // 2)
                dict_window.geometry(f"{width}x{height}+{x}+{y}")

        # 绑定双击事件
        columns_tree.bind("<Double-1>", edit_dict_id)

        # 底部按钮
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=10)

        # 保存关系表按钮
        ttk.Button(
            btn_frame,
            text="保存代码集关系",
            command=lambda: self.save_field_dict_relations(),
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="关闭", command=column_window.destroy).pack(
            side=tk.RIGHT
        )

        # 设置窗口位置居中
        column_window.update_idletasks()
        width = column_window.winfo_width()
        height = column_window.winfo_height()
        x = (column_window.winfo_screenwidth() // 2) - (width // 2)
        y = (column_window.winfo_screenheight() // 2) - (height // 2)
        column_window.geometry(f"{width}x{height}+{x}+{y}")

        # 让窗口获取焦点
        column_window.focus_set()

    def generate_rules(self):
        # 获取选中的表
        selected_items = self.table_tree.selection()
        if not selected_items:
            messagebox.showwarning("警告", "请选择至少一个表")
            return

        selected_tables = []
        for item in selected_items:
            table_name = self.table_tree.item(item)["values"][0]
            for table in self.tables:
                if table["name"] == table_name:
                    selected_tables.append(table)
                    break

        # 获取规则选择
        rules = {
            "空值检查": self.null_var.get(),
            "长度检查": self.length_check_var.get(),
            "枚举值检查": self.enum_check_var.get(),
        }

        # 如果没有选择任何规则，给出警告
        if not any(rules.values()):
            messagebox.showwarning("警告", "请选择至少一种规则类型")
            return

        # 计算总规则数量
        rule_count = self.count_rules(selected_tables, rules)

        # 确认操作
        clear_message = (
            "\n注意：已勾选清空现有规则选项，将会删除所选表字段上的所有现有规则!"
            if self.clear_existing_rules.get()
            else ""
        )
        result = messagebox.askokcancel(
            "确认",
            f"将为 {len(selected_tables)} 个表创建约 {rule_count} 条规则，是否继续?{clear_message}",
        )

        if result:
            self.create_rules(selected_tables, rules)

    def count_rules(self, tables, rules):
        count = 0
        for table in tables:
            for column in table["columns"]:
                if rules["空值检查"] and column["not_null"]:
                    count += 1
                if rules["长度检查"] and column["max_length"]:
                    count += 1
                if rules["枚举值检查"] and column["is_enum"]:
                    count += 1
        return count

    def create_rules(self, tables, rules):
        """创建数据质量规则，包含计时功能"""
        self.log("开始创建规则...")
        self.status_var.set("创建规则中...")

        # 使用线程避免UI冻结
        def create_task():
            import time

            # 记录开始时间
            start_time = time.time()

            try:
                job_count, rule_count = 0, 0
                deleted_rules = 0
                api_base_url = self.api_url.get().rstrip("/")
                data_source_id = self.data_source_id.get()
                database_name = self.database_name.get()
                log_file_path = self.log_file.get()

                # 获取认证头
                headers = self.get_auth_headers()

                # 首先获取数据库UUID
                try:
                    database_url = (
                        f"{api_base_url}/datasource/{data_source_id}/databases"
                    )
                    self.root.after(
                        0, lambda: self.log(f"获取数据库信息: {database_url}")
                    )

                    db_response = requests.get(database_url, headers=headers)
                    if (
                        db_response.status_code != 200
                        or db_response.json().get("code") != 200
                    ):
                        self.root.after(
                            0,
                            lambda: self.log(f"获取数据库列表失败: {db_response.text}"),
                        )

                        # 计算耗时并显示错误状态
                        end_time = time.time()
                        total_time = end_time - start_time
                        minutes = int(total_time // 60)
                        seconds = total_time % 60
                        time_str = (
                            f"{minutes}分{seconds:.2f}秒"
                            if minutes > 0
                            else f"{seconds:.2f}秒"
                        )
                        self.root.after(
                            0,
                            lambda ts=time_str: self.status_var.set(
                                f"获取数据库失败 (耗时: {ts})"
                            ),
                        )
                        return

                    # 查找当前数据库的UUID
                    database_uuid = None
                    for db in db_response.json().get("data", []):
                        if db.get("name") == database_name:
                            database_uuid = db.get("uuid")
                            break

                    if not database_uuid:
                        self.root.after(
                            0, lambda: self.log(f"未找到数据库 {database_name} 的UUID")
                        )

                        # 计算耗时并显示错误状态
                        end_time = time.time()
                        total_time = end_time - start_time
                        minutes = int(total_time // 60)
                        seconds = total_time % 60
                        time_str = (
                            f"{minutes}分{seconds:.2f}秒"
                            if minutes > 0
                            else f"{seconds:.2f}秒"
                        )
                        self.root.after(
                            0,
                            lambda ts=time_str: self.status_var.set(
                                f"未找到数据库 (耗时: {ts})"
                            ),
                        )
                        return

                    self.root.after(
                        0,
                        lambda: self.log(
                            f"数据库 {database_name} 的UUID: {database_uuid}"
                        ),
                    )
                except Exception as e:
                    self.root.after(
                        0, lambda e=e: self.log(f"获取数据库UUID异常: {str(e)}")
                    )

                    # 计算耗时并显示错误状态
                    end_time = time.time()
                    total_time = end_time - start_time
                    minutes = int(total_time // 60)
                    seconds = total_time % 60
                    time_str = (
                        f"{minutes}分{seconds:.2f}秒"
                        if minutes > 0
                        else f"{seconds:.2f}秒"
                    )
                    self.root.after(
                        0,
                        lambda ts=time_str: self.status_var.set(
                            f"获取数据库异常 (耗时: {ts})"
                        ),
                    )
                    return

                # 缓存表和字段的UUID
                table_uuids = {}
                column_uuids = {}

                with open(log_file_path, "w", encoding="utf-8") as log_file:
                    for table in tables:
                        table_name = table["name"]

                        # 获取表UUID (如果尚未缓存)
                        if table_name not in table_uuids:
                            try:
                                table_url = f"{api_base_url}/datasource/{data_source_id}/{database_name}/tables"
                                self.root.after(
                                    0, lambda: self.log(f"获取表 {table_name} 信息...")
                                )

                                table_response = requests.get(
                                    table_url, headers=headers
                                )
                                if (
                                    table_response.status_code != 200
                                    or table_response.json().get("code") != 200
                                ):
                                    self.root.after(
                                        0,
                                        lambda: self.log(
                                            f"获取表列表失败: {table_response.text}"
                                        ),
                                    )
                                    continue

                                # 查找当前表的UUID
                                for tb in table_response.json().get("data", []):
                                    # 使用upper()进行不区分大小写的比较
                                    table_uuids[tb.get("name").upper()] = tb.get("uuid")

                                # 同样在查找时也使用upper()转换为大写进行比较
                                if table_name.upper() not in table_uuids:
                                    self.root.after(
                                        0,
                                        lambda t=table_name: self.log(
                                            f"未找到表 {t} 的UUID"
                                        ),
                                    )
                                    continue
                            except Exception as e:
                                self.root.after(
                                    0,
                                    lambda t=table_name, e=e: self.log(
                                        f"获取表 {t} UUID异常: {str(e)}"
                                    ),
                                )
                                continue

                        table_uuid = table_uuids.get(table_name.upper())
                        self.root.after(
                            0,
                            lambda t=table_name, u=table_uuid: self.log(
                                f"处理表: {t} (UUID: {u}) - {table['comment']}"
                            ),
                        )

                        # 获取该表所有字段的UUID
                        try:
                            if table_name not in column_uuids:
                                column_uuids[table_name] = {}

                            column_url = (
                                f"{api_base_url}/catalog/list/column/{table_uuid}"
                            )
                            column_response = requests.get(column_url, headers=headers)

                            if (
                                column_response.status_code != 200
                                or column_response.json().get("code") != 200
                            ):
                                self.root.after(
                                    0,
                                    lambda t=table_name: self.log(
                                        f"获取表 {t} 的字段列表失败: {column_response.text}"
                                    ),
                                )
                                continue

                            # 缓存该表所有字段的UUID，将字段名转为大写存储
                            for col in column_response.json().get("data", []):
                                column_uuids[table_name][col.get("name").upper()] = (
                                    col.get("uuid")
                                )

                        except Exception as e:
                            self.root.after(
                                0,
                                lambda t=table_name, e=e: self.log(
                                    f"获取表 {t} 字段UUID异常: {str(e)}"
                                ),
                            )
                            continue

                        for column in table["columns"]:
                            column_name = column["name"]

                            # 检查是否有该字段的UUID，使用大写进行比较
                            if column_name.upper() not in column_uuids.get(
                                table_name, {}
                            ):
                                self.root.after(
                                    0,
                                    lambda t=table_name, c=column_name: self.log(
                                        f"未找到表 {t} 字段 {c} 的UUID"
                                    ),
                                )
                                continue

                            # 获取字段UUID时也使用大写进行匹配
                            column_uuid = column_uuids[table_name][column_name.upper()]

                            # 如果勾选了清空规则选项，则先删除现有规则
                            if self.clear_existing_rules.get():
                                try:
                                    # 查询字段现有的规则
                                    metrics_url = f"{api_base_url}/catalog/page/entity/metric?pageSize=100&pageNumber=1&total=0&uuid={column_uuid}"
                                    self.root.after(
                                        0,
                                        lambda c=column_name: self.log(
                                            f"  查询字段 {c} 现有规则..."
                                        ),
                                    )

                                    metrics_response = requests.get(
                                        metrics_url, headers=headers
                                    )

                                    if (
                                        metrics_response.status_code == 200
                                        and metrics_response.json().get("code") == 200
                                    ):
                                        metrics_data = metrics_response.json().get(
                                            "data", {}
                                        )
                                        metrics = metrics_data.get("records", [])

                                        if metrics:
                                            self.root.after(
                                                0,
                                                lambda c=column_name, n=len(
                                                    metrics
                                                ): self.log(
                                                    f"  找到字段 {c} 的 {n} 条现有规则，正在删除..."
                                                ),
                                            )

                                            # 删除每一个规则
                                            for metric in metrics:
                                                job_id = metric.get("id")
                                                job_name = metric.get(
                                                    "name", "未命名规则"
                                                )

                                                if job_id:
                                                    delete_url = (
                                                        f"{api_base_url}/job/{job_id}"
                                                    )
                                                    delete_response = requests.delete(
                                                        delete_url, headers=headers
                                                    )

                                                    if (
                                                        delete_response.status_code
                                                        == 200
                                                        and delete_response.json().get(
                                                            "code"
                                                        )
                                                        == 200
                                                    ):
                                                        self.root.after(
                                                            0,
                                                            lambda j=job_name: self.log(
                                                                f"    已删除规则: {j}"
                                                            ),
                                                        )
                                                        deleted_rules += 1
                                                    else:
                                                        self.root.after(
                                                            0,
                                                            lambda j=job_name, r=delete_response.text: self.log(
                                                                f"    删除规则失败 {j}: {r}"
                                                            ),
                                                        )
                                    else:
                                        self.root.after(
                                            0,
                                            lambda c=column_name, r=metrics_response.text: self.log(
                                                f"  获取字段 {c} 规则列表失败: {r}"
                                            ),
                                        )

                                except Exception as e:
                                    self.root.after(
                                        0,
                                        lambda c=column_name, e=e: self.log(
                                            f"  查询/删除字段 {c} 规则异常: {str(e)}"
                                        ),
                                    )

                            # 生成规则参数
                            parameters = generate_rule_parameters(
                                table, column, database_name, rules, self.code_dicts
                            )

                            if parameters:
                                for param in parameters:
                                    rule_name = param[
                                        "name"
                                    ]  # 使用规则名称作为作业名称

                                    # 创建作业
                                    try:
                                        # 构造新接口的请求体
                                        payload = {
                                            "entityUuid": column_uuid,  # 使用字段的UUID
                                            "jobCreate": {
                                                "type": "DATA_QUALITY",
                                                "dataSourceId": str(data_source_id),
                                                "engineType": "local",
                                                "retryTimes": 0,
                                                "retryInterval": 1,
                                                "timeout": 36000,
                                                "timeoutStrategy": 0,
                                                "parameter": json.dumps(
                                                    [param]
                                                ),  # 注意这里是单个规则
                                                "jobName": rule_name,  # 使用规则名称
                                                "runningNow": 0,
                                            },
                                        }

                                        self.root.after(
                                            0,
                                            lambda j=rule_name: self.log(
                                                f"  创建作业: {j}"
                                            ),
                                        )

                                        # 使用POST方法调用新接口
                                        response = requests.post(
                                            f"{api_base_url}/catalog/add-metric",
                                            headers=headers,
                                            json=payload,
                                        )

                                        if (
                                            response.status_code == 200
                                            and response.json().get("code") == 200
                                        ):
                                            job_id = response.json().get("data")
                                            log_file.write(
                                                f"作业ID: {job_id}, 作业名称: {rule_name}, 字段: {column_name}\n"
                                            )
                                            job_count += 1
                                            rule_count += 1
                                        else:
                                            self.root.after(
                                                0,
                                                lambda r=response.text: self.log(
                                                    f"  创建失败: {r}"
                                                ),
                                            )
                                    except Exception as e:
                                        self.root.after(
                                            0,
                                            lambda e=e: self.log(
                                                f"  请求异常: {str(e)}"
                                            ),
                                        )

                # 计算总用时
                end_time = time.time()
                total_time = end_time - start_time
                minutes = int(total_time // 60)
                seconds = total_time % 60
                time_str = (
                    f"{minutes}分{seconds:.2f}秒" if minutes > 0 else f"{seconds:.2f}秒"
                )

                # 删除规则的统计信息
                if self.clear_existing_rules.get():
                    self.root.after(
                        0, lambda dr=deleted_rules: self.log(f"已删除 {dr} 条现有规则")
                    )

                self.root.after(
                    0,
                    lambda jc=job_count, rc=rule_count, ts=time_str: self.log(
                        f"任务完成! 共创建 {jc} 个作业，{rc} 条规则。总耗时: {ts}"
                    ),
                )
                self.root.after(
                    0, lambda f=log_file_path: self.log(f"创建记录已保存到 {f}")
                )
                self.root.after(
                    0, lambda ts=time_str: self.status_var.set(f"完成 (耗时: {ts})")
                )

            except Exception as e:
                import traceback

                error_msg = traceback.format_exc()

                # 计算错误情况下的总用时
                end_time = time.time()
                total_time = end_time - start_time
                minutes = int(total_time // 60)
                seconds = total_time % 60
                time_str = (
                    f"{minutes}分{seconds:.2f}秒" if minutes > 0 else f"{seconds:.2f}秒"
                )

                self.root.after(
                    0, lambda: self.log(f"创建规则错误: {str(e)}\n{error_msg}")
                )
                self.root.after(
                    0, lambda ts=time_str: self.status_var.set(f"创建失败 (耗时: {ts})")
                )

        threading.Thread(target=create_task).start()

    def browse_code_dict_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filepath:
            self.code_dict_file.set(filepath)
            self.log("已选择代码字典表: " + filepath)

            default_dict = resource_path("all_dictionaries.json")
            if filepath != default_dict and os.path.exists(default_dict):
                self.log(
                    "注意: 您选择了非默认代码字典文件，默认文件为: " + default_dict
                )

            self.load_code_dict_file(filepath)

    def browse_field_relation_file(self):
        filepath = filedialog.askopenfilename(
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")]
        )
        if filepath:
            self.field_dict_relation_file.set(filepath)
            self.log("已选择字段代码集关系表: " + filepath)

            default_relations = resource_path("field_dict_relations.json")
            if filepath != default_relations and os.path.exists(default_relations):
                self.log(
                    "注意: 您选择了非默认关系文件，默认文件为: " + default_relations
                )

            self.load_field_relation_file(filepath)

    def load_code_dict_file(self, filepath):
        """加载代码字典表文件"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                self.code_dicts = json.load(f)
            self.log(f"成功加载 {len(self.code_dicts)} 个代码字典")
        except Exception as e:
            self.log(f"加载代码字典表文件失败: {str(e)}")
            messagebox.showerror("错误", f"无法加载代码字典表文件: {str(e)}")

    def load_field_relation_file(self, filepath):
        """加载字段代码集关系表文件"""
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                self.field_dict_relations = json.load(f)
            self.log(f"成功加载 {len(self.field_dict_relations)} 个字段代码集关系")
        except Exception as e:
            self.log(f"加载字段代码集关系表文件失败: {str(e)}")

    def update_field_dict_relation(
        self, table_name, column_name, dict_id, multi_select=False, separator="^"
    ):
        """添加或更新字段与代码集的关系"""
        # 检查是否已存在关系
        for relation in self.field_dict_relations:
            if (
                relation.get("table_name", "").upper() == table_name.upper()
                and relation.get("colmun_name", "").upper() == column_name.upper()
            ):
                # 更新现有关系
                relation["dict_id"] = dict_id
                relation["multi_select"] = multi_select  # 多选标识
                relation["separator"] = separator  # 分隔符

                # 更新所有表中该字段的枚举标识
                for table in self.tables:
                    if table["name"].upper() == table_name.upper():
                        for column in table["columns"]:
                            if column["name"].upper() == column_name.upper():
                                column["is_enum"] = True  # 设置为枚举字段
                                column["multi_select"] = multi_select  # 设置多选标识
                                column["separator"] = separator  # 设置分隔符
                                break
                        break

                return

        # 添加新关系
        self.field_dict_relations.append(
            {
                "table_name": table_name,
                "colmun_name": column_name,
                "dict_id": dict_id,
                "multi_select": multi_select,
                "separator": separator,
            }
        )

        # 更新所有表中该字段的枚举标识
        for table in self.tables:
            if table["name"].upper() == table_name.upper():
                for column in table["columns"]:
                    if column["name"].upper() == column_name.upper():
                        column["is_enum"] = True  # 设置为枚举字段
                        column["multi_select"] = multi_select  # 设置多选标识
                        column["separator"] = separator  # 设置分隔符
                        break
                break

    def remove_field_dict_relation(self, table_name, column_name):
        """移除字段与代码集的关系"""
        self.field_dict_relations = [
            relation
            for relation in self.field_dict_relations
            if not (
                relation.get("table_name", "").upper() == table_name.upper()
                and relation.get("colmun_name", "").upper() == column_name.upper()
            )
        ]

        # 更新所有表中该字段的枚举标识
        for table in self.tables:
            if table["name"].upper() == table_name.upper():
                for column in table["columns"]:
                    if column["name"].upper() == column_name.upper():
                        column["is_enum"] = False  # 移除枚举字段标识
                        break
                break

    def save_field_dict_relations(self):
        """保存字段代码集关系到文件"""
        filepath = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json"), ("All Files", "*.*")],
            initialfile="field_dict_relations.json",
        )

        if not filepath:
            return

        try:
            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(self.field_dict_relations, f, ensure_ascii=False, indent=2)
            self.field_dict_relation_file.set(filepath)
            messagebox.showinfo("成功", f"字段代码集关系表已保存到: {filepath}")
            self.log(f"字段代码集关系表已保存到: {filepath}")
        except Exception as e:
            messagebox.showerror("错误", f"保存字段代码集关系表失败: {str(e)}")
            self.log(f"保存字段代码集关系表失败: {str(e)}")


# 解析SQL文件函数
def parse_sql(file_path):
    """
    解析SQL文件，返回一个字典：
    {table_name: {column_name: {'type': ..., 'required': bool, 'comment': ...} } }
    解析思路：从"CREATE TABLE"开始，到"  ) COMMENT"结束之间获取表定义，
    再逐行提取以反引号(`)开头的字段定义。
    """
    tables = {}
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()

    # 按 "CREATE TABLE" 分割，每一段包含一个表定义
    segments = content.split("CREATE TABLE")
    for seg in segments[1:]:
        # seg中找到结束位置)"  ) COMMENT"
        end_pos = seg.rfind(") COMMENT")
        if end_pos == -1:
            continue  # 没有找到则跳过
        table_def = seg[:end_pos]
        # 表名可能出现在第一行在反引号中。例如：`Z2010` (或可能有前后空格)
        # 获取表名：在table_def中找到第一个 "(" 之前的部分，再提取其中的反引号里内容
        pre_paren = table_def.split("(", 1)[0]
        pre_paren = pre_paren.strip()

        # 表名通常用反引号括起
        if pre_paren.startswith("`"):
            end_bt = pre_paren.find("`", 1)
            table_name = pre_paren[1:end_bt].strip()
        else:
            # 备选：取第一个单词
            table_name = pre_paren.split()[0].strip()

        # 表注释部分：从end_pos开始向后查找
        comment_part = seg[end_pos:]
        comment_match = re.search(r"COMMENT\s*'([^']*)'", comment_part)
        table_comment = comment_match.group(1) if comment_match else ""

        # 获取字段部分：从第一个 "("开始，用换行分割
        paren_pos = table_def.find("(")
        if paren_pos == -1:
            continue

        fields_str = table_def[paren_pos + 1 :]
        # 按行分割
        lines = fields_str.splitlines()
        columns = {}
        columns["__table_comment__"] = table_comment  # 存储表注释

        for line in lines:
            line = line.strip().rstrip(",")
            # 如果行以反引号开头，则认为是字段定义
            if not line.startswith("`"):
                continue

            # 字段名在第一个反引号内
            end_bt = line.find("`", 1)
            if end_bt == -1:
                continue

            col_name = line[1:end_bt]
            # 去除字段名后剩余部分
            rest = line[end_bt + 1 :].strip()
            # 以空格分割，第一个token为数据类型
            tokens = rest.split()
            if not tokens:
                continue

            col_type = tokens[0]  # 数据类型（包括括号内容）

            # 判断 NOT NULL 是否存在
            required = "NOT NULL" in rest.upper()

            # 获取 COMMENT 内容
            comment = ""
            comment_match = re.search(r"COMMENT\s*'([^']*)'", rest)
            if comment_match:
                comment = comment_match.group(1)
            else:
                comment = col_name  # 没有注释则使用字段名

            columns[col_name] = {
                "type": col_type,
                "required": required,
                "comment": comment,
            }

        # 只添加有字段的表
        if len(columns) > 1:  # 排除只有__table_comment__的空表
            tables[table_name] = columns

    return tables


# 生成枚举值正则表达式
def generate_enum_regexp(enum_codes, separator="^"):
    """
    为多选代码集生成正则表达式
    例如：代码集为['01','02']，生成正则 ^(01|02)(\^(01|02))*$
    """
    # 清除空格并处理引号
    clean_codes = [code.strip().replace("'", "") for code in enum_codes]
    # 创建代码选择模式
    pattern = "|".join(clean_codes)
    # 构建完整的正则表达式：以一个代码开始，后面可以跟0或多个分隔符+代码
    escaped_separator = re.escape(separator)
    return f"^({pattern})({escaped_separator}({pattern}))*$"


# 生成规则参数
def generate_rule_parameters(
    table, column, database_name, rule_options, code_dicts=None
):
    parameters = []

    # 1. 空值检查 - 针对NOT NULL字段
    if rule_options["空值检查"] and column["not_null"]:
        parameters.append(
            {
                "metricType": "column_null",
                "expectedType": "fix_value",
                "resultFormula": "diff-actual-expected",
                "operator": "eq",
                "threshold": "0",
                "metricParameter": {
                    "database": database_name,
                    "table": table["name"],
                    "column": column["name"],
                },
                "expectedParameter": {"expected_value": "0"},  # 期望没有数据为空
                "name": f"{column['comment']} - 空值检查",
                "uuid": str(uuid.uuid4()),
            }
        )

    # 2. 字段长度检查 - 针对VARCHAR字段
    if rule_options["长度检查"] and column["max_length"]:
        parameters.append(
            {
                "metricType": "column_length",
                "expectedType": "fix_value",
                "resultFormula": "diff-actual-expected",
                "operator": "eq",
                "threshold": "0",
                "metricParameter": {
                    "database": database_name,
                    "table": table["name"],
                    "column": column["name"],
                    "comparator": ">",
                    "length": str(column["max_length"]),
                },
                "expectedParameter": {"expected_value": "0"},
                "name": f"{column['comment']} - 长度检查(>{column['max_length']})",
                "uuid": str(uuid.uuid4()),
            }
        )

    # 3. 枚举值检查 - 针对可能的枚举字段
    if rule_options["枚举值检查"] and column["is_enum"]:
        # 获取代码集ID
        dict_id = column.get("dict_id")
        is_multi_select = column.get("multi_select", False)
        separator = column.get("separator", "^")
        enum_values = ""

        # 如果设置了代码集且提供了代码字典，则使用代码字典中的值
        if dict_id and code_dicts:
            # 查找对应的代码集
            for dict_item in code_dicts:
                if dict_item.get("dict_id") == dict_id:
                    # 提取代码值
                    codes = [
                        code.get("code", "") for code in dict_item.get("codes", [])
                    ]
                    if codes:
                        enum_values = ",".join(codes)
                    break

        rule_name = f"{column['comment']} - 枚举值检查"
        if dict_id:
            dict_name = column.get("dict_name", "")
            if dict_name:
                rule_name = f"{column['comment']} - 枚举值检查 ({dict_name})"

        # 判断字段类型，决定是否需要为枚举值添加引号
        column_type = column.get("type", "").upper()
        is_string_type = any(
            t in column_type for t in ["VARCHAR", "CHAR", "TEXT", "STRING"]
        )
        # 字段是否可为null
        is_nullable = not column["not_null"]

        if is_multi_select:
            # 使用正则表达式验证多选值
            enum_codes = enum_values.split(",")
            if is_string_type:
                # 字符串类型，为每个值添加引号
                enum_codes = [f"'{code.strip()}'" for code in enum_codes]

            # 生成正则表达式
            regexp = generate_enum_regexp(enum_codes, separator)

            # 匹配出不匹配的值
            parameters.append(
                {
                    "metricType": "column_match_not_regex",
                    "expectedType": "fix_value",
                    "resultFormula": "diff-actual-expected",
                    "operator": "eq",
                    "threshold": "0",
                    "metricParameter": {
                        "database": database_name,
                        "table": table["name"],
                        "column": column["name"],
                        "regexp": regexp,
                        # 若可为NULL，则需在其不为NULL时检查
                        "filter": (
                            f"{column['name']} IS NOT NULL" if is_nullable else ""
                        ),
                    },
                    "expectedParameter": {"expected_value": "0"},
                    "name": f"{rule_name} (多选)",
                    "uuid": str(uuid.uuid4()),
                }
            )
        else:
            # 单选情况，使用原有的枚举检查
            enum_list = ""
            if is_string_type:
                # 字符串类型，为每个值添加引号
                enum_list = ",".join([f"'{v.strip()}'" for v in enum_values.split(",")])
            else:
                # 数字类型，不添加引号
                enum_list = enum_values

            parameters.append(
                {
                    "metricType": "column_not_in_enums",
                    "expectedType": "fix_value",
                    "resultFormula": "diff-actual-expected",
                    "operator": "eq",
                    "threshold": "0",
                    "metricParameter": {
                        "database": database_name,
                        "table": table["name"],
                        "column": column["name"],
                        "enum_list": enum_list,
                        "filter": (
                            f"{column['name']} IS NOT NULL" if is_nullable else ""
                        ),
                    },
                    "expectedParameter": {"expected_value": "0"},
                    "name": rule_name,
                    "uuid": str(uuid.uuid4()),
                }
            )

    return parameters


def resource_path(relative_path):
    """Get absolute path to resource, works for dev and for PyInstaller"""
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        # base_path = os.path.abspath(".")
        base_path = os.path.dirname(os.path.abspath(sys.argv[0]))

    return os.path.join(base_path, relative_path)


def main():
    try:
        root = tk.Tk()
        app = DatavinesUI(root)
        root.mainloop()
    except Exception as e:
        import traceback

        error_msg = traceback.format_exc()
        # 确保异常被记录到文件
        error_log_path = os.path.join(
            os.path.dirname(os.path.abspath(sys.argv[0])), "error.log"
        )
        with open(error_log_path, "w", encoding="utf-8") as f:
            f.write(f"程序发生错误:\n{error_msg}")
        # 尝试显示错误信息
        try:
            messagebox.showerror(
                "程序错误", f"程序发生错误:\n{str(e)}\n详情请查看error.log文件"
            )
        except:
            pass


if __name__ == "__main__":
    main()
