🚀 快速开始
方式一：直接下载使用（推荐）
# 下载主程序文件
wget https://raw.githubusercontent.com/194268/spf-email-scanner/main/spf_scanner.py
# 或者使用curl
curl -O https://raw.githubusercontent.com/194268/spf-email-scanner/main/spf_scanner.py
方式二：克隆整个仓库
git clone https://github.com/194268/spf-email-scanner.git
cd spf-email-scanner
安装依赖
pip install dnspython
1. 准备域名列表文件
创建 domains.txt 文件，每行一个域名：
text
example.com
github.com
company.com
http://www.baidu.com
https://twitter.com
2. 基础扫描命令
bash
python spf_scanner.py -f domains.txt --to-addr your-email@example.com
3. 完整参数示例
bash
python spf_scanner.py \
  -f domains.txt \
  --to-addr receiver@example.com \
  --subject "安全测试邮件" \
  --body "这是一封SPF漏洞测试邮件" \
  -v 2
⚙️ 参数详解
参数	说明	是否必需	示例
-f, --file	域名列表文件路径	是	-f domains.txt
--to-addr	接收测试邮件的邮箱地址	是	--to-addr test@example.com
--subject	邮件主题	否	--subject "测试邮件"
--body	邮件内容	否	--body "测试内容"
-v, --verbose	输出详细程度：0-简洁 1-正常 2-详细	否	-v 2
--test-all	测试所有域名（默认只测试有漏洞的）	否	--test-all
--smtp-user	SMTP用户名（如需认证）	否	--smtp-user username
--smtp-pass	SMTP密码（如需认证）	否	--smtp-pass password
-c, --crazy-mode	持续发送模式	否	-c
🎯 使用示例
示例1：快速漏洞扫描
bash
# 只扫描有SPF漏洞的域名并进行测试
python spf_scanner.py -f domains.txt --to-addr your@gmail.com
示例2：详细模式测试所有域名
bash
# 详细输出，测试文件中的所有域名
python spf_scanner.py -f domains.txt --to-addr admin@company.com --test-all -v 2
示例3：自定义邮件内容
bash
python spf_scanner.py -f domains.txt \
  --to-addr security@company.com \
  --subject "重要：安全配置检测" \
  --body "您的邮件系统可能存在安全风险，请及时检查SPF配置。" \
  -v 1
示例4：需要SMTP认证的情况
bash
python spf_scanner.py -f domains.txt \
  --to-addr target@example.com \
  --smtp-user your_username \
  --smtp-pass your_password \
  -v 2
📊 输出说明
工具提供三种输出模式：

简洁模式 (-v 0)：只显示进度和最终结果

正常模式 (-v 1)：显示漏洞扫描结果和测试摘要

详细模式 (-v 2)：显示所有详细信息，包括DNS查询和SMTP交互过程
