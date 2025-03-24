# DataVines数据质量规则配置工具

## 概述

DataVines数据质量规则配置工具是一个图形化应用程序，用于批量创建和管理DataVines平台上的数据质量规则。该工具通过解析数据库表结构定义文件（SQL DDL），自动为表字段生成多种类型的数据质量检查规则，包括空值检查、长度检查和枚举值检查。

## 功能特点

- **自动解析SQL表结构**：支持解析标准SQL DDL文件，识别表名、字段名、数据类型、约束和注释

- **可视化表字段管理**：以表格形式显示解析的表结构，方便查看和选择

- **代码字典管理**：支持导入和管理代码字典，用于枚举值检查

- **字段与代码集关联**：可为特定字段关联代码集，支持单选和多选模式

- 多种质量规则

  ：支持生成三种基本数据质量规则：

  - 空值检查：针对非空字段，检查是否有空值
  - 长度检查：针对有长度限制的字段，检查是否超出长度限制
  - 枚举值检查：针对关联了代码集的字段，检查值是否在允许范围内

- **批量规则创建**：一次性为多个表的多个字段创建数据质量规则

- **现有规则管理**：可选择清空现有规则后再创建新规则

- **操作日志**：详细记录操作过程和结果

## 系统要求

- Windows操作系统
- Python 3.6+
- 需要的Python库：
  - tkinter (通常随Python安装)
  - requests

## 安装和使用

### 方法1：直接使用Python脚本

1. 确保已安装Python 3.6+
2. 安装所需依赖：`pip install requests`
3. 下载脚本文件`datavines_job_creator.py`
4. 运行脚本：`python datavines_job_creator.py`

### 方法2：使用打包的可执行文件

1. 下载预编译的可执行文件（如果有提供）
2. 双击运行应用程序

## 使用指南

### 基本配置

1. **SQL文件**：选择包含表结构定义的SQL文件
2. **API地址**：设置DataVines API的基础URL，通常以`/api/v1`结尾
3. **认证令牌**：输入DataVines的认证令牌
4. **数据源ID**：指定要操作的数据源ID
5. **数据库名**：指定要操作的数据库名称

### 代码字典管理

1. **代码字典表**：选择或创建包含代码字典的JSON文件，格式如下：

   ```
   [{
     "dict_id": "1",
     "dict_name": "性别",
     "codes": [
   		{"code": "M", "name": "男"},
   		{"code": "F", "name": "女"}
     ]
   }]
   ```

   

2. **字段代码集关系**：选择或创建包含字段与代码集关系的JSON文件，格式如下：

   ```
   [{
     "table_name": "Z2010",
     "colmun_name": "Z201010",
     "dict_id": "CZ001"
   }]
   ```

### 操作流程

1. 加载SQL文件并点击**解析表结构**按钮
2. 查看解析出的表列表，确认表结构正确
3. 可以双击表名查看详细字段信息，并设置字段的代码集关联
4. 选择要创建规则的表（可使用**选择全部**按钮）
5. 勾选需要生成的规则类型（空值检查、长度检查、枚举值检查）
6. 点击**生成规则**按钮开始创建规则
7. 在执行日志区域查看操作进度和结果

## 配置文件说明

### 默认文件

程序会自动寻找以下默认文件：

- [default_ddl.sql](vscode-file://vscode-app/d:/Microsoft VS Code/resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)：默认的SQL表结构定义文件
- [all_dictionaries.json](vscode-file://vscode-app/d:/Microsoft VS Code/resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)：默认的代码字典文件
- [field_dict_relations.json](vscode-file://vscode-app/d:/Microsoft VS Code/resources/app/out/vs/code/electron-sandbox/workbench/workbench.html)：默认的字段代码集关系文件

这些文件应放置在程序的同一目录下。

### 日志文件

- 操作日志会保存在指定的日志文件中，默认为程序目录下的`datavines_jobs_created.log`
- 如果程序发生错误，错误日志会保存在程序目录下的`error.log`文件中

## 注意事项

1. SQL文件格式需要符合标准SQL DDL语法，建议使用VSCode的Prettier SQL插件格式化
2. 确保DataVines API地址和认证令牌正确，可使用"测试连接"按钮验证
3. 创建规则前，建议先确保字段与代码集的关系正确设置
4. 批量创建规则可能需要一定时间，请耐心等待
5. 勾选"清空现有规则"选项将删除选定表字段上的所有现有规则，请谨慎使用

## 故障排除

1. 如果无法连接到DataVines API，请检查API地址和认证令牌是否正确
2. 如果解析SQL文件失败，请检查SQL文件格式是否符合要求
3. 如果创建规则失败，请查看执行日志了解详细错误信息
4. 遇到其他问题，请查看`error.log`文件获取更多信息

## 开发者信息

此工具用于简化DataVines数据质量规则的创建和管理过程，尤其适合需要批量创建数据质量规则的场景。