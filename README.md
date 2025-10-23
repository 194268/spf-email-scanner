# 🚀 快速开始

方式一：直接下载使用（推荐）

# 下载主程序文件
wget https://raw.githubusercontent.com/194268/spf-email-scanner/main/spf_scanner.py

或者使用curl

curl -O https://raw.githubusercontent.com/194268/spf-email-scanner/main/spf_scanner.py

方式二：克隆整个仓库

git clone https://github.com/194268/spf-email-scanner.git

cd spf-email-scanner

# 安装依赖

pip install dnspython

# 📋 使用方法

1.准备域名列表

   创建 domains.txt 文件，每行一个域名:
   
   example.com
   
   github.com
   
   company.com
   
   http://www.baidu.com
   
   https://twitter.com
   
2.基础扫描命令

   python spf_scanner.py -f domains.txt --to-addr your-email@example.com
   
3. 完整参数示例
   
   python spf_scanner.py \
   
  -f domains.txt \
  
  --to-addr receiver@example.com \
  
  --subject "安全测试邮件" \
  
  --body "这是一封SPF漏洞测试邮件" \
  
  -v 2
  
# ⚙️ 参数详解

-f, --file	域名列表文件路径		-f domains.txt

--to-addr	接收测试邮件的邮箱地址		--to-addr test@example.com

--subject	邮件主题		--subject "测试邮件"

--body	邮件内容		--body "测试内容"

-v, --verbose	输出详细程度：0-简洁 1-正常 2-详细		-v 2

--test-all	测试所有域名（默认只测试有漏洞的）		--test-all

--smtp-user	SMTP用户名（如需认证）		--smtp-user username

--smtp-pass	SMTP密码（如需认证）		--smtp-pass password

-c, --crazy-mode	持续发送模式		-c
   
