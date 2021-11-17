#！/bin/bash
#@Auth：tj
#@Time：2020/12/21——2020/12/23
dash_line="------------------------------------------------------------------"
#file="check.txt"
#绿色字体输出检测通过

pass=$(($pass+1))
print_pass(){
    echo -e "\033[32m++> PASS \033[0m"
    #echo "++> PASS""$1" >> "$file"
}
# 红色字体输出检测失败FAIL
fail=$(($fail+1))
print_fail(){
  echo -e "\033[31m--> FAIL \033[0m"
  #echo "--> FAIL""$1" >> "$file"
}
# 黄色字体输出需手工再检查的项
print_manual_check(){
  echo -e "\033[33m##> Manual \033[0m"
  #echo "##> Manual""$1" >> "$file"
}

#白色字为找不到文件
print_white(){
	echo -e "\033[37m$1 \033[0m"
	#echo "##>123456 ""$1" >> "$file"
}

# 蓝色字体输出补充
print_info(){
  echo -e "\033[34m$1 \033[0m"
  #echo "$1" >> "$file"
}
# 紫色字体输出检测项
print_check_point(){
  echo ""
  echo -e "\033[35m[No."$1"] "$2" \033[0m"
  #echo "[$1]"" $2" >> "$file"
}
print_dot_line(){
	echo "$dash_line"
  	#echo "$dash_line" >> "$file"
  	#echo "$1" >> "$file"
}
print_summary(){
  # 输出显示
  print_info "---------------------------- Summary -----------------------------"
  echo -e "\033[35m全部检测项: $1 \033[0m"
  echo -e "\033[32m通过检测项: $2 \033[0m"
  echo -e "\033[31m失败检测项: $3 \033[0m"
  echo -e "\033[33m手工检测项: $4 \033[0m"
  #print_info "检测结果将写入文件 $file中..."
  print_info "$dash_line"
  # 写入文件
  echo "---------------------------- Summary -----------------------------" >> "$csvFile"
  echo "全部检测项: $1" >> "$csvFile"
  echo "通过检测项: $2" >> "$csvFile"
  echo "失败检测项: $3" >> "$csvFile"
  echo "手工检测项: $4" >> "$csvFile"
  echo "$dash_line" >> "$csvFile"
}
# ====================================
begin_msg="-------------------- 正在执行操作系统基线检查 --------------------"
print_info "$begin_msg"
index=0       # 检测项编号
pass=0        # 通过的检测项数
fail=0        # 未通过的检测项数
manual=0      # 需手工复核的检测项数



#ip=`ifconfig -a |grep inet |grep -v 127.0.0.1 |grep -v inet6 |awk  '{print $2}'`

#echo "$ip"
#csvFile="$ip.csv"
#echo "$csvFile"
#echo "$begin_msg" > "$file"

csvFile="checkList.csv"
echo "$csvFile"
echo "章节	检查项	级别	调整要求	检查项说明	标准值	检查情况	符合性	调整情况	原因" >> "$csvFile"
check_point="账号口令-2.1：检查是否设置口令生存周期"
index=$(($index+1))
print_check_point $index "$check_point"
#在文件etc/login.defs中搜索pass_max_days的值，并且去掉#自开头的值
#grep -v ^#    ------>  不匹配以#开头的行
passmax=`cat /etc/login.defs | grep PASS_MAX_DAYS | grep -v ^#`
print_info "'PASS_MAX_DAYS 应介于1~90'"

print_info "$passmax"
if [ -n "$passmax" ]; then
	days=`echo $passmax | awk '{print $2}'`

	if [ "$days" -gt 90 ]; then
		echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$days	FAIL	 	 " >> "$csvFile"
		fail=$((fail+1))
		print_fail
	else
		pass=$(($pass+1))
		print_pass
		echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	$days	TRUE	 	 " >> "$csvFile"
	fi
else
	fail=$(($fail+1))
	print_fail
	echo "2.1	检查是否以设置口令生存周期	重要	建议调整	长期不修改密码会增加密码暴露风险，除入域服务器或服务器超管账号分段管理无需配置外，应对服务器密码最长使用期限进行限制。此检查项建议调整	<=90	无此配置	FAIL	 	 " >> "$csvFile"
fi
print_dot_line

#check_point="账号口令-2:检查是否设置口令更改最小间隔天数 "
#index=$(($index+1))
#print_check_point $index "$check_point"
#passmin=`cat /etc/login.defs | grep PASS_MIN_DAYS | grep -v ^#`
#print_info "'PASS_MIN_DAYS 应大于等于 7'"

#print_info "$passmin"
#if [ -n "$passmin" ]; then
#  days=`echo $passmin | awk '{print $2}'`
#  if [ "$days" -lt 7 ]; then
#	echo "2.2	检查是否设置口令更改最小间隔天数	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应##为8位。此检查项建议调整	>=8	$days	FAIL" >> "$csvFile"
#      fail=$(($fail+1))
#      print_fail
#  else
#	echo "2.2	检查是否设置口令更改最小间隔天数	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应#为8位。此检查项建议调整	>=8	$days	TRUE"  >> "$csvFile"
#      pass=$(($pass+1))
#      print_pass
#  fi
#else
#  echo "2.2	检查是否设置口令更改最小间隔天数	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	null	FAIL" >> "$csvFile"
#  fail=$(($fail+1))
#  print_fail
#fi
#print_dot_line

check_point="账号口令-2.2:检查是否设置口令最小长度 "
index=$(($index+1))
print_check_point $index "$check_point"
passminlen=`cat /etc/login.defs | grep PASS_MIN_LEN | grep -v ^#`
print_info "'PASS_MIN_LEN 应大于等于 8'"

print_info "$passminlen"
if [ -n "$passminlen" ]; then
  days=`echo $passminlen | awk '{print $2}'`
  if [ "$days" -lt 8 ]; then
	echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	$days	FAIL		" >> "$csvFile"
      fail=$(($fail+1))
      print_fail
  else
	echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	$days	TRUE		" >> "$csvFile"
      pass=$(($pass+1))
      print_pass
  fi
else
  echo "2.2	检查是否设置口令最小长度	重要	建议调整	密码长度过短会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，口令长度最小值应为8位。此检查项建议调整	>=8	null	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="账号口令-2.3:检查是否设置口令过期警告天数 "
index=$(($index+1))
print_check_point $index "$check_point"
passwarn=`cat /etc/login.defs | grep PASS_WARN_AGE | grep -v ^#`
print_info "'PASS_WARN_AGE 应大于等于 30'"
print_info "$passwarn"
if [ -n "$passwarn" ]; then
  days=`echo $passwarn | awk '{print $2}'`
  if [ "$days" -lt 30 ]; then
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	FAIL	 	" >> "$csvFile"
      fail=$(($fail+1))
      print_fail
  else
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	TRUE	 	">> "$csvFile"
      pass=$(($pass+1))
      print_pass
  fi
else
	echo "2.3	检查是否设置口令过期警告天数	重要	建议调整	除入域服务器超管账号分段管理无需配置外，应配置密码过期提醒策略防止密码过期无法登陆。此检查项建议调整	>=30	20	FAIL	 	" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="账号口令-2.4:检查设备密码复杂度策略 "
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'系统应设置密码复杂度策略，避免设置账号弱口令'"

print_info "此部分要求不一，请手工检查/etc/pam.d/system-auth或/etc/security/pwquality.conf文件配置"
print_info "此处检查内容为，密码长度至少8位，并且存在大写字母、小写字母、特殊字符、数字至少一个的要求来检测的"

print_info "检查/etc/pam.d/system-auth，如下："
flag=0
info=`cat /etc/pam.d/system-auth | grep password | grep requisite`
print_info "$info"
#line=`cat /etc/pam.d/system-auth | grep password | grep pam_cracklib.so | grep -v ^#`
if [ -n "$info" ]; then
    # minlen:密码字符串长度，dcredit数字字符个数，ucredit大写字符个数，ocredit特殊字符个数，lcredit小写字符个数

    	#minlen=`echo $info | awk -F 'minlen=' '{print $2}' | awk -F ' ' '{print $1}'`
    dcredit=`echo $info | awk -F 'dcredit=' '{print $2}' | awk -F '' '{print $2}'`
    ucredit=`echo $info | awk -F 'ucredit=' '{print $2}' | awk -F '' '{print $2}'`
    ocredit=`echo $info | awk -F 'ocredit=' '{print $2}' | awk -F '' '{print $2}'`
    lcredit=`echo $info | awk -F 'lcredit=' '{print $2}' | awk -F '' '{print $2}'`
echo "$dcredit"
    if [ "$dcredit" -eq 1 ] && [ "$ucredit" -eq 1 ] && [ "$lcredit" -eq 1 ] && [ "$ocredit" -eq 1 ]; then
        print_info "dcredit => ""[ $dcredit ]"
        print_info "ucredit => ""[ $ucredit ]"
        print_info "ocredit => ""[ $ocredit ]"
        print_info "lcredit => ""[ $lcredit ]"
        flag=1
    fi
fi

 # 以下检查/etc/security/pwquality.conf文件中的内容
 # minlen为密码字符串长度，minclass为字符类别
print_info "检查/etc/security/pwquality.conf，如下:"
line_minlen=`cat /etc/security/pwquality.conf | grep minlen | grep -v ^#`
line_minclass=`cat /etc/security/pwquality.conf | grep minclass | grep -v ^#`

if [ -n "$line_minlen" ] && [ -n "$line_minclass" ]; then
	minlen=`echo "$line_minlen" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
	minclass=`echo "$line_minclass" | awk -F "=" '{print $2}' | awk '{gsub(/^\s+|\s+$/， "");print}'`
	if [ "$minlen" -ge 6 ] && [ "$minclass" -ge 4 ];then

    	print_info "minlen =>"" [ $minlen ]"
    	print_info "minclass =>"" [ $minclass ]"
    	flag=1

    fi
fi


if [ "$flag" -eq 1 ]; then
	pass=$(($pass+1))
	echo "2.4	检查设备密码复杂度策略	重要	建议调整	密码复杂度过低会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码复杂度应包含特殊字符、大小写字母。此检查项建议调整	至少有1个大写字母、1个小写字母、1个数字、1个特殊字符	null	TRUE	 	" >> "$csvFile"
	print_pass
else
	echo "2.4	检查设备密码复杂度策略	重要	建议调整	密码复杂度过低会增加密码被爆破风险，按照企业密码管理要求与等级保护标准，密码复杂度应包含特殊字符、大小写字母。此检查项建议调整	至少有1个大写字母、1个小写字母、1个数字、1个特殊字符	null	FAIL	 	" >> "$csvFile"
	fail=$(($fail+1))
	print_fail


fi

print_dot_line
check_point="口令策略-2.5 :检查是否存在空口令账号"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'不允许存在空口令的账号'"

tmp=`/bin/cat /etc/shadow | /bin/awk -F: '($2 == "" ) { print "user " $1 " does not have a password "}'`
print_info '空口令账号:'"[ $tmp ]"
if [ -z "$tmp" ]; then
  echo "2.5	检查是否存在空口令账户	重要	建议调整	由于空口令会让攻击者不需要口令进入系统，存在较大风险。此检查项建议调整	不存在空口令账户	$tmp	TRUE	 	" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
  echo "2.5	检查是否存在空口令账户	重要	建议调整	由于空口令会让攻击者不需要口令进入系统，存在较大风险。此检查项建议调整	不存在空口令账户	$tmp	FAIL	 	" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line
check_point="帐号管理-2.6:检查是否设置除root之外UID为0的用户"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'任何UID为0的帐户都具有系统上的超级用户特权，只有root账号的uid才能为0'"


result=`/bin/cat /etc/passwd | /bin/awk -F: '($3 == 0) { print $1 }'`
print_info "UID为0的用户如下:"
print_info "[ $result ]"

if [ "root" = $result  ]; then
	echo "2.6	检查是否设置除root之外UID为0的用户	一般	建议调整	不可设置除root之外，第二个具有root权限的账户。此检查项建议调整	root	$result	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "2.6	检查是否设置除root之外UID为0的用户	一般	建议调整	不可设置除root之外，第二个具有root权限的账户。此检查项建议调整	root	$result	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi

print_dot_line

check_point="认证授权-3.1:检查用户umask设置"
echo "3.1	检查用户umask设置	一般	建议调整	umask配置后，创建系统用户时所赋予的权限为最高权限减去umask设置的权限，保证所创建用户不可创建其他权限用户。此检查项建议调整	umask077	参考子项目	参考子项		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "用户权限要求不严格可设置为027，严格可设置为077"

#设置flag=1，若有一项不合格，则flag=0
flag=1
print_info "检查/etc/csh.cshrc文件中umask设置："
umask1=`/bin/cat /etc/csh.cshrc | grep umask | /bin/awk -F 'umask' 'NR==1{print $2}'`

print_info "/etc/csh.cshrc中umask===>""[ $umask1 ]"


if [ "$umask1" -eq 077 ] || [ "$umask1" -eq 027 ]; then
	echo "3.1.1	检查/etc/csh.cshrc中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask1	TRUE		" >> "$csvFile"
	print_pass
else
	echo "3.1.1	检查/etc/csh.cshrc中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask1	FAIL		" >> "$csvFile"
	flag=0
	print_fail
fi

#print_info "检查/etc/csh.login中的umask设置"
#umask2=`cat /etc/csh.login | grep umask`
#print_info "/etc/csh.login中的umask===>""[ $umask2 ]"
#if [ -n "$umask2" ]; then
#	umask2_1=`echo "$umask2" | awk -F 'umask' 'NR==1{print $2}'`
#	if [ "$umask2_1" -eq 077 ] || [ "$umask2_1" -eq 027 ]; then
#	echo "3.1.2	检查/etc/csh.login中的umask设置	一般	建议调整	详情参考父项#3.1	077/027	$umask2_1	TRUE		" >> "$csvFile"
#	
#	print_pass
#	else
#		echo "3.1.2	检查/etc/csh.login中的umask设置	一般	建议调整	详情参##考父项3.1	077/027	$umask2_1	FAIL		" >> "$csvFile"
#		print_info "umask的值不正确"
#		flag=0
#		print_fail
#	fi
#else
#	echo "3.1.2	检查/etc/csh.login中的umask设置	一般	建议调整	详情参考父项3.1	077/027	umask为空，请添加	FAIL		" >> "$csvFile"
#	print_info "umask为空，请在/etc/sch.login中添加umask=077或者027"
#	flag=0
#	print_fail
#fi

print_info "检查/etc/bashrc文件中umask设置："
umask3=`/bin/cat /etc/bashrc | grep umask | /bin/awk -F 'umask' 'NR==2{print $2}' `
print_info "/etc/bashrc中umask===>""[ $umask3 ]"

if [ "$umask3" -eq 077 ] || [ "$umask3" -eq 027 ]; then
	echo "3.1.2	检查/etc/bashrc文件中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask3	TRUE		" >> "$csvFile"
	print_pass
else
	echo "3.1.2	检查/etc/bashrc文件中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask3	FAIL		" >> "$csvFile"
	flag=0
	print_fail
fi

print_info "检查/etc/profile文件中umask设置："
umask4=`/bin/cat /etc/profile | grep umask | /bin/awk -F 'umask' 'NR==2{print $2}' `
print_info "/etc/profile中umask===>""[ $umask4 ]"

if [ "$umask4" -eq 077 ] || [ "$umask4" -eq 027 ]; then
	echo "3.1.3	检查/etc/profile文件中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask4	TRUE		" >> "$csvFile"
	print_pass
else
	echo "3.1.3	检查/etc/profile文件中umask设置	一般	建议调整	详情参考父项3.1	077/027	$umask4	FAIL		" >> "$csvFile"
	flag=0
	print_fail
fi


if [ "$flag" -eq 1 ]; then
	pass=$(($pass+1))
	
else
	fail=$(($fail+1))
	
fi
print_dot_line

check_point="认证授权-3.2:检查重要目录或文件权限设置"
echo "3.2	检查重要目录或文件权限设置	一般	自行判断	需检查重要目录或文件权限设置是否合规，保障系统安全性，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "检查重要目录或文件权限设置"

flag1=1
print_info "检查/etc/xinetd.conf文件权限："
xineted_file="/etc/xineted.conf"
if [ -f "$xineted_file" ]; then
	xineted_stat=`stat -c %a /etc/xineted.conf`
	print_info "/etc/xinted.conf的权限应该大于等于600，实际为：===>""$xineted_stat"
	if [ "$xineted_stat" -ge 600 ]; then
		echo "3.2.1	检查/etc/xinetd.conf文件权限	一般	自行判断	参考父项3.2	>=600	$xineted_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.1	检查/etc/xinetd.conf文件权限	一般	自行判断	参考父项3.2	>=600	$xineted_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.1	检查/etc/xinetd.conf文件权限	一般	自行判断	参考父项3.2	>=600	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/group文件权限："
group_file="/etc/group"
if [ -f "$group_file" ]; then
	group_stat=`stat -c %a /etc/group`
	print_info "/etc/group的权限应该大于等于644，实际为：===>""$group_stat"
	if [ "$group_stat" -ge 644 ]; then
		echo "3.2.2	检查/etc/group文件权限	一般	自行判断	参考父项3.2	>=644	$group_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.2	检查/etc/group文件权限	一般	自行判断	参考父项3.2	>=644	$group_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.2	检查/etc/group文件权限	一般	自行判断	参考父项3.2	>=644	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi


print_info "检查/etc/shadow文件权限："
shadow_file="/etc/shadow"
if [ -f "$shadow_file" ]; then
	shadow_stat=`stat -c %a /etc/shadow`
	print_info "/etc/shadow的权限应该大于等于400，实际为：===>""$shadow_stat"
	if [ "$shadow_stat" -ge 400 ]; then
		echo "3.2.3	检查/etc/shadow文件权限	一般	自行判断	参考父项3.2	>=400	$shadow_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.3	检查/etc/shadow文件权限	一般	自行判断	参考父项3.2	>=400	$shadow_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.3	检查/etc/shadow文件权限	一般	自行判断	参考父项3.2	>=400	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/services文件权限："
services_file="/etc/services"
if [ -f "$shadow_file" ]; then
	services_stat=`stat -c %a /etc/services`
	print_info "/etc/services的权限应该大于等于644，实际为：===>""$services_stat"
	if [ "$services_stat" -ge 644 ]; then
		echo "3.2.4	检查/etc/services文件权限	一般	自行判断	参考父项3.2	>=644	$services_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.4	检查/etc/services文件权限	一般	自行判断	参考父项3.2	>=644	$services_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.4	检查/etc/services文件权限	一般	自行判断	参考父项3.2	>=644	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/security目录权限："
security_file="/etc/security"
if [ -d "$security_file" ]; then
	security_stat=`stat -c %a /etc/security`
	print_info "/etc/security的权限应该大于等于600，实际为：===>""$security_stat"
	if [ "$security_stat" -ge 600 ]; then
		echo "3.2.5	检查/etc/security目录权限	一般	自行判断	参考父项3.2	>=600	$security_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.5	检查/etc/security目录权限	一般	自行判断	参考父项3.2	>=600	$security_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.5	检查/etc/security目录权限	一般	自行判断	参考父项3.2	>=600	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/passwd文件权限："
passwd_file="/etc/passwd"
if [ -f "$passwd_file" ]; then
	passwd_stat=`stat -c %a /etc/passwd`
	print_info "/etc/passwd的权限应该大于等于644，实际为：===>""$passwd_stat"
	if [ "$passwd_stat" -ge 644 ]; then
		echo "3.2.6	检查/etc/passwd文件权限	一般	自行判断	参考父项3.2	>=644	$passwd_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.6	检查/etc/passwd文件权限	一般	自行判断	参考父项3.2	>=644	$passwd_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.6	检查/etc/passwd文件权限	一般	自行判断	参考父项3.2	>=644	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/rc6.d目录权限："
rc6_file="/etc/rc6.d"
if [ -d "$rc6_file" ]; then
	rc6_stat=`stat -c %a /etc/rc6.d`
	print_info "/etc/rc6.d的权限应该大于等于750，实际为：===>""$rc6_stat"
	if [ "$rc6_stat" -ge 750 ]; then
		echo "3.2.7	检查/etc/rc6.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc6_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.7	检查/etc/rc6.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc6_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.7	检查/etc/rc6.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc0.d目录权限："
rc0_file="/etc/rc0.d"
if [ -d "$rc0_file" ]; then
	rc0_stat=`stat -c %a /etc/rc0.d`
	print_info "/etc/rc0.d的权限应该大于等于750，实际为：===>""$rc0_stat"
	if [ "$rc0_stat" -ge 750 ]; then
		echo "3.2.8	检查/etc/rc0.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc0_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.8	检查/etc/rc0.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc0_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.8	检查/etc/rc0.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc1.d目录权限："
rc1_file="/etc/rc1.d"
if [ -d "$rc1_file" ]; then
	rc1_stat=`stat -c %a /etc/rc1.d`
	print_info "/etc/rc1.d的权限应该大于等于750，实际为：===>""$rc1_stat"
	if [ "$rc1_stat" -ge 750 ]; then
		echo "3.2.9	检查/etc/rc1.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc1_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.9	检查/etc/rc1.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc1_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.9	检查/etc/rc1.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc2.d目录权限："
rc2_file="/etc/rc2.d"
if [ -d "$rc2_file" ]; then
	rc2_stat=`stat -c %a /etc/rc2.d`
	print_info "/etc/rc2.d的权限应该大于等于750，实际为：===>""$rc2_stat"
	if [ "$rc2_stat" -ge 750 ]; then
		echo "3.2.10	检查/etc/rc2.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc2_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.10	检查/etc/rc2.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc2_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.10	检查/etc/rc2.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc目录权限："
etc_file="/etc"
if [ -d "$etc_file" ]; then
	etc_stat=`stat -c %a /etc`
	print_info "/etc/的权限应该大于等于750，实际为：===>""$etc_stat"
	if [ "$etc_stat" -ge 750 ]; then
		echo "3.2.11	检查/etc目录权限	一般	自行判断	参考父项3.2	>=750	$etc_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.11	检查/etc目录权限	一般	自行判断	参考父项3.2	>=750	$etc_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.11	检查/etc目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc4.d目录权限："
rc4_file="/etc/rc4.d"
if [ -d "$rc4_file" ]; then
	rc4_stat=`stat -c %a /etc/rc4.d`
	print_info "/etc/rc4.d的权限应该大于等于750，实际为：===>""$rc4_stat"
	if [ "$rc4_stat" -ge 750 ]; then
		echo "3.2.12	检查/etc/rc4.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc4_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.12	检查/etc/rc4.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc4_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.12	检查/etc/rc4.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc5.d目录权限："
rc5_file="/etc/rc5.d"
if [ -d "$rc5_file" ]; then
	rc5_stat=`stat -c %a /etc/rc5.d`
	print_info "/etc/rc5.d的权限应该大于等于750，实际为：===>""$rc5_stat"
	if [ "$rc5_stat" -ge 750 ]; then
		echo "3.2.13	检查/etc/rc5.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc5_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.13	检查/etc/rc5.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc5_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.13	检查/etc/rc5.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc3.d目录权限："
rc3_file="/etc/rc3.d"
if [ -d "$rc3_file" ]; then
	rc3_stat=`stat -c %a /etc/rc3.d`
	print_info "/etc/rc3.d的权限应该大于等于750，实际为：===>""$rc3_stat"
	if [ "$rc3_stat" -ge 750 ]; then
		echo "3.2.14	检查/etc/rc3.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc3_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.14	检查/etc/rc3.d目录权限	一般	自行判断	参考父项3.2	>=750	$rc3_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.14	检查/etc/rc3.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/rc.d/init.d目录权限："
init_file="/etc/rc.d/init.d"
if [ -d "$init_file" ]; then
	init_stat=`stat -c %a /etc/rc.d/init.d`
	print_info "/etc/rc.d/init.d的权限应该大于等于750，实际为：===>""$init_stat"
	if [ "$init_stat" -ge 750 ]; then
		echo "3.2.15	检查/etc/rc.d/init.d目录权限	一般	自行判断	参考父项3.2	>=750	$init_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.15	检查/etc/rc.d/init.d目录权限	一般	自行判断	参考父项3.2	>=750	$init_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.15	检查/etc/rc.d/init.d目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	TRUE		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/tmp目录权限："
tmp_file="/tmp"
if [ -d "$tmp_file" ]; then
	tmp_stat=`stat -c %a /tmp`
	print_info "/tmp的权限应该大于等于750，实际为：===>""$tmp_stat"
	if [ "$tmp_stat" -ge 750 ]; then
		echo "3.2.16	检查/tmp目录权限	一般	自行判断	参考父项3.2	>=750	$tmp_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.16	检查/tmp目录权限	一般	自行判断	参考父项3.2	>=750	$tmp_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.16	检查/tmp目录权限	一般	自行判断	参考父项3.2	>=750	目录不存在	FAIL		" >> "$csvFile"
	print_white "目录不存在！"

fi

print_info "检查/etc/grub.conf文件权限："
grub_file="/etc/grub.conf"
if [ -d "$grub_file" ]; then
	grub_stat=`stat -c %a /etc/grub.conf`
	print_info "/etc/grub.conf的权限应该大于等于600，实际为：===>""$grub_stat"
	if [ "$grub_stat" -ge 600 ]; then
		echo "3.2.17	检查/etc/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	$grub_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.17	检查/etc/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	$grub_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.17	检查/etc/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	目录不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/grub/grub.conf文件权限："
grub1_file="/etc/grub/grub.conf"
if [ -d "$grub1_file" ]; then
	grub1_stat=`stat -c %a /etc/grub/grub.conf`
	print_info "/etc/grub/grub.conf的权限应该大于等于600，实际为：===>""$grub1_stat"
	if [ "$grub1_stat" -ge 600 ]; then
		echo "3.2.18	检查/etc/grub/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	$grub1_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.18	检查/etc/grub/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	$grub1_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.18	检查/etc/grub/grub.conf文件权限	一般	自行判断	参考父项3.2	>=600	文件不存在	TRUE		 ">> "$csvFile"
	print_white "文件不存在！"

fi

print_info "检查/etc/lilo.conf文件权限："
lilo_file="/etc/lilo.conf"
if [ -d "$lilo_file" ]; then
	lilo_stat=`stat -c %a /etc/lilo.conf`
	print_info "/etc/lilo.conf的权限应该大于等于600，实际为：===>""$lilo_stat"
	if [ "$lilo_stat" -ge 600 ]; then
		echo "3.2.19	检查/etc/lilo.conf文件权限	一般	自行判断	参考父项3.2	>=600	$lilo_stat	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "3.2.19	检查/etc/lilo.conf文件权限	一般	自行判断	参考父项3.2	>=600	$lilo_stat	FAIL		" >> "$csvFile"
		flag1=0
		print_fail
	fi
else
	echo "3.2.19	检查/etc/lilo.conf文件权限	一般	自行判断	参考父项3.2	>=600	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi

if [ "$flag1" -eq 1 ];then
	pass=$(($pass+1))
else
	fail=$(($fail+1))
fi
print_dot_line


check_point="认证授权-3:检查重要文件属性设置"

echo "3.3	检查重要文件属性设置	一般	建议调整	需检查重要目录或文件属性设置是否合规，保障系统安全性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项	 	" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "'应设置重要文件为i属性（如：chattr +i /etc/passwd），设定文件不能删除、改名、设定链接关系等'"

flag2=1
print_info "检查/etc/passwd的文件属性"
lsattr_pass=`lsattr /etc/passwd | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_pass=`lsattr /etc/passwd`
print_info "/etc/passwd的属性值为:""$lsattr1_pass"
if [ "$lsattr_pass"x = "i"x  ]; then
  echo "3.3.1	检查/etc/passwd的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_pass	TRUE	 	" >> "$csvFile"
  print_pass
else
	echo "3.3.1	检查/etc/passwd的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_pass	FAIL	 	" >> "$csvFile"
  flag2=0
  print_fail
fi

print_info "检查/etc/shadow的文件属性"
lsattr_sha=`lsattr /etc/shadow | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_sha=`lsattr /etc/shadow`
print_info "/etc/shadow的属性值为:""$lsattr1_sha"
if [ "$lsattr_sha"x = "i"x  ]; then
 echo "3.3.2	检查/etc/shadow的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_sha	TRUE	 	" >> "$csvFile"
  print_pass
else
	echo "3.3.2	检查/etc/shadow的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_sha	FAIL	 	" >> "$csvFile"
  flag2=0
  print_fail
fi

print_info "检查/etc/group的文件属性"
lsattr_gro=`lsattr /etc/group | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_gro=`lsattr /etc/group`
print_info "/etc/group的属性值为:""$lsattr1_gro"
if [ "$lsattr_gro"x = "i"x  ]; then
  echo "3.3.3	检查/etc/group的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_gro	TRUE	 	" >> "$csvFile"
  print_pass
else
	echo "3.3.3	检查/etc/group的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_gro	FAIL	 	" >> "$csvFile"
  flag2=0
  print_fail
fi

print_info "检查/etc/gshadow的文件属性"
lsattr_gsh=`lsattr /etc/gshadow | awk '{ print $1 }' | awk -F- '{print $5}'`
lsattr1_gsh=`lsattr /etc/gshadow`
print_info "/etc/group的属性值为:""$lsattr1_gsh"
if [ "$lsattr_gsh"x = "i"x  ]; then
  echo "3.3.4	检查/etc/gshadow的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_gsh	TRUE	 	" >> "$csvFile"
  print_pass
else
	echo "3.3.4	检查/etc/gshadow的文件属性	一般	建议调整	参考父项3.3	i	$lsattr_gsh	FAIL	 	" >> "$csvFile"
  flag2=0
  print_fail
fi

if [ "$flag2" -eq 1 ]; then
	pass=$(($pass+1))
else
	fail=$(($fail+1))
fi
print_dot_line



check_point="认证授权-3.4:检查用户目录缺省访问权限设置 "
index=$(($index+1))
print_check_point $index "$check_point"
tmp=`cat /etc/login.defs | grep umask | grep -v ^#`
tmp1=`cat /etc/login.defs | grep UMASK | grep -v ^#`
print_info "'文件目录缺省访问权限应是 027 '"

print_info "实际检测值为:"
print_info "[ $tmp ]"
tt=`echo $tmp | grep 027`
tt1=`echo $tmp1 | grep 027`
if [ -n "$tt" ] || [ -n "$tt1" ];then
	echo "3.4	检查用户目录缺省访问权限设置	重要	建议调整	控制用户缺省访问权限，当在创建新文件或目录时应屏蔽掉新文件或目录不应有的访问允许权限，防止同属于改组的其他用户及别的组的用户修改用户的文件或更高限制。此检查项建议调整	027	$tt	TRUE		" >> "$csvFile"
  	pass=$(($pass+1))
  	print_pass
else
	echo "3.4	检查用户目录缺省访问权限设置	重要	建议调整	控制用户缺省访问权限，当在创建新文件或目录时应屏蔽掉新文件或目录不应有的访问允许权限，防止同属于改组的其他用户及别的组的用户修改用户的文件或更高限制。此检查项建议调整	027	$tt	FAIL		" >> "$csvFile"
	print_info "设置 umask 027 "
  	fail=$(($fail+1))
  	print_fail
fi
print_dot_line

check_point="认证授权-3.5:检查是否设置SSH登录前警告Banner"
index=$(($index+1))
print_check_point $index "$check_point"
banner1=`cat /etc/ssh/sshd_config | grep Banner`
print_info "'检查SSH配置文件:/etc/ssh/sshd_config，未启用banner或合理设置banner的内容'"

print_info "$banner1"
# 如果banner为空或者为 None，则符合要求
if [ -z "$banner1" ]; then
	echo "3.5	检查是否设置SSH登录前警告Banner	可选	建议调整	检查是否设置ssh登陆前的警告Banner信息，警示登陆系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$banner1	TRUE		" >> "$csvFile"
  print_info "不存在Banner配置项"
  pass=$(($pass+1))
  print_pass
else
  banner2=`cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}' | grep -v "none"`
  if [ -n "$banner2" ]; then
	echo "3.5	检查是否设置SSH登录前警告Banner	可选	建议调整	检查是否设置ssh登陆前的警告Banner信息，警示登陆系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$banner2	TRUE		" >> "$csvFile"
    print_info "未配置Banner路径文件"
    pass=$(($pass+1))
    print_pass
  else
	echo "3.5	检查是否设置SSH登录前警告Banner	可选	建议调整	检查是否设置ssh登陆前的警告Banner信息，警示登陆系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$banner2	MANUAL		" >> "$csvFile"
    manual=$(($manual+1))
    path=`cat /etc/ssh/sshd_config | grep Banner | awk '{print $2}'`
    print_info "请手工检查文件 $path 是否符合要求"
    print_manual_check
  fi
fi
print_dot_line

check_point="日志审计-4.1:检查是否配置远程日志功能"
echo "4.1	检查是否配置远程日志功能	可选	建议调整	应对远程日至进行筛选与审核。此检查项建议调整	参考《Linux安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'在远程主机上存储日志数据保护日志完整性免受本地攻击'"

msg="请检查/etc/rsyslog.conf文件，查看是否配置日志服务器"
print_info "$msg"
manual=$(($manual+1))
print_manual_check
print_dot_line

#check_point="日志审计-4.2:检查是否记录用户对设备的操作"
#echo "4.2	检查是否记录用户对设备的操作	可选	建议调整	应对远程日至进行筛选与审核。此检查项建议调整	参考《Linux安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
#index=$(($index+1))
#print_check_point $index "$check_point"
#print_info "'检查是否记录用户对设备的操作'"

#msg="请检查/var/log/pacct文件，这一功能默认不开放，需要安装pacct工具。酌情是否检查加固！"
#print_info "$msg"
#manual=$(($manual+1))
#print_manual_check
#print_dot_line


check_point="日志审计-4.2:检查安全事件日志配置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'设备应配置日志功能，记录对与设备相关的安全事件'"

tmp=`cat /etc/rsyslog.conf | grep /var/log/messages | egrep '\*.info;mail.none;authpriv.none;cron.none' | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 /var/log/messages 的配置如下所示:"
print_info "$tmp"
if [ -n "$tmp" ]; then
	echo "4.2	检查安全事件日志配置	可选	建议调整	应对安全时间日志文件进行配置。此检查项建议调整	参考《Linux安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"	
  pass=$(($pass+1))
  print_pass
else
	echo "4.2	检查安全事件日志配置	可选	建议调整	应对安全时间日志文件进行配置。此检查项建议调整	参考《Linux安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="日志审计-4.3:检查日志文件是否全局可写"
echo "4.3	检查日志文件是否全局可写	可选	建议调整	应配置日志文件非全局可写，保证日至不可篡改。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"

flag3=1
print_info "检查/var/log/cron"

cron_file=`find /var/log/cron`
if [ -n "$cron_file" ]; then
	cron=`stat -c %a /var/log/cron`
	print_info "var/log/cron的权限应大于等于755||实际为：""$cron"
	if [ "$cron" -ge 755 ]; then
		echo "4.3.1	检查/var/log/cron	可选	建议调整	参考父项4.4	>=755	$cron	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.1	检查/var/log/cron	可选	建议调整	参考父项4.4	>=755	$cron	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.1	检查/var/log/cron	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi










print_info "检查/var/log/secure"


secure_file=`find /var/log/secure`
if [ -n "$secure_file" ]; then
	secure=`stat -c %a /var/log/secure`
	print_info "var/log/cron的权限应大于等于755||实际为：""$secure"
	if [ "$secure" -ge 755 ]; then
		echo "4.3.2	检查/var/log/secure	可选	建议调整	参考父项4.4	>=755	$secure	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.2	检查/var/log/secure	可选	建议调整	参考父项4.4	>=755	$secure	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.2	检查/var/log/secure	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



print_info "检查/var/log/messages"

messages_file=`find /var/log/messages`
if [ -n "$messages_file" ]; then
	messages=`stat -c %a /var/log/messages`
	print_info "var/log/messages的权限应大于等于755||实际为：""$messages"
	if [ "$messages" -ge 755 ]; then
		echo "4.3.3	检查/var/log/messages	可选	建议调整	参考父项4.4	>=755	$messages	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.3	检查/var/log/messages	可选	建议调整	参考父项4.4	>=755	$messages	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.3	检查/var/log/messages	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



print_info "检查/var/log/boot.log"

boot_file=`find /var/log/boot.log`
if [ -n "$boot_file" ]; then
	boot=`stat -c %a /var/log/boot.log`
	print_info "var/log/boot.log的权限应大于等于755||实际为：""$boot"
	if [ "$boot" -ge 755 ]; then
		echo "4.3.4	检查/var/log/boot.log	可选	建议调整	参考父项4.4	>=755	$boot	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.4	检查/var/log/boot.log	可选	建议调整	参考父项4.4	>=755	$boot	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi

else
	echo "4.3.4	检查/var/log/boot.log	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



print_info "检查/var/log/mail"

mail_file=`find /var/log/mail`
if [ -n "$mail_file" ]; then
	mail=`stat -c %a /var/log/mail`
	print_info "var/log/mail的权限应大于等于755||实际为：""$mail"
	if [ "$mail" -ge 755 ]; then
		echo "4.3.5	检查/var/log/mail	可选	建议调整	参考父项4.4	>=755	$mail	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.5	检查/var/log/mail	可选	建议调整	参考父项4.4	>=755	$mail	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.5	检查/var/log/mail	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



print_info "检查/var/log/localmessages"

localmessages_file=`find /var/log/localmessages`
if [ -n "$localmessages_file" ]; then
	localmessages=`stat -c %a /var/log/localmessages`
	print_info "var/log/localmessages的权限应大于等于755||实际为：""$localmessages"
	if [ "$localmessages" -ge 755 ]; then
		echo "4.3.6	检查/var/log/localmessages	可选	建议调整	参考父项4.4	>=755	$localmessages	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.6	检查/var/log/localmessages	可选	建议调整	参考父项4.4	>=755	$localmessages	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.6	检查/var/log/localmessages	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi


print_info "检查/var/log/spooler"


spooler_file=`find /var/log/spooler`
if [ -n "$spooler_file" ]; then
	spooler=`stat -c %a /var/log/spooler`
	print_info "var/log/spooler的权限应大于等于755||实际为：""$spooler"
	if [ "$spooler" -ge 755 ]; then
		echo "4.3.7	检查/var/log/spooler	可选	建议调整	参考父项4.4	>=755	$spooler	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.7	检查/var/log/spooler	可选	建议调整	参考父项4.4	>=755	$spooler	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.7	检查/var/log/spooler	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



print_info "检查/var/log/maillog"

maillog_file=`find /var/log/maillog`
if [ -n "$maillog_file" ]; then
	maillog=`stat -c %a /var/log/maillog`
	print_info "var/log/maillog的权限应大于等于755||实际为：""$maillog"
	if [ "$maillog" -ge 755 ]; then
		echo "4.3.8	检查/var/log/maillog	可选	建议调整	参考父项4.4	>=755	$maillog	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "4.3.8	检查/var/log/maillog	可选	建议调整	参考父项4.4	>=755	$maillog	FAIL		" >> "$csvFile"
		flag3=0
		print_fail
	fi
else
	echo "4.3.8	检查/var/log/maillog	可选	建议调整	参考父项4.4	>=755	文件不存在	TRUE		" >> "$csvFile"
	print_white "文件不存在！"

fi



if [ "$flag3" -eq 1 ]; then
	pass=$(($pass+1))
else
	fail=$(($fail+1))
fi
print_dot_line


#check_point="日志审计-4.5:检查是否启用cron行为日志功能"
#echo "4.5	检查是否启用cron行为日志功能	可选	自行判断	应启用记录cron行为日至的功能。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
#index=$(($index+1))
#print_check_point $index "$check_point"
#print_info "'检查是否启用cron行为日志功能'"

#msg="请检查/etc/rsyslog.conf文件，查看是否配置日志服务器"
#print_info "$msg"
#manual=$(($manual+1))
#print_manual_check
#print_dot_line

check_point="日志审计-4.4:检查是否对登录进行日志记录"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'设备应配置日志功能，对用户登录进行记录，记录内容包括用户登录使用的账号，登录是否成功，登录时间，以及远程登录时，用户使用的IP地址'"
tmp=`cat /etc/rsyslog.conf | grep /var/log/secure | egrep 'authpriv'.\('info|\*'\) | grep -v ^#`

print_info "/etc/rsyslog.conf 文件中 authpriv 的配置如下所示:"
print_info "$tmp"
if [ -n "$tmp" ]; then
echo "4.4	检查是否对登录进行日志记录	重要	建议调整	应对登录时间日志文件进行配置，保证日志的完整性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "4.4	检查是否对登录进行日志记录	重要	建议调整	应对登录时间日志文件进行配置，保证日志的完整性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="日志审计-4.5:检查是否配置su命令使用情况记录"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'启用syslog系统日志审计功能'"

tmp=`cat /etc/rsyslog.conf | grep /var/log/secure | egrep 'authpriv'.\('info|\*'\) | grep -v ^#`
print_info "/etc/rsyslog.conf 文件中 authpriv 的配置如下所示:"
print_info "$tmp"
if [ -n "$tmp" ]; then
echo "4.5	检查是否配置su命令使用情况记录	可选	建议调整	应配置su命令使用情况记录，保证高权限命令可审计。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
print_pass
else
	echo "4.5	检查是否配置su命令使用情况记录	可选	建议调整	应配置su命令使用情况记录，保证高权限命令可审计。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
print_fail
fi
print_dot_line

#check_point="协议安全-5.1:检查是否禁止root用户远程登录"
#echo "5.1	检查是否禁止root用户远程登录	重要	自行判断	应禁止root用户远程登录，防止针对root用户暴力破解密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项		" >> "$csvFile"
#index=$(($index+1))
#print_check_point $index "$check_point"
#print_info "'检查是否禁止用户远程登录，酌情检查加固！'"

#flag4=1
#print_info "检查是否禁止root用户远程telnet登录"
#stelnet=`cat /etc/pam.d/login | grep auth | grep required | grep pam_securetty.so`
#if [ -n "$stelnet" ]; then
#	echo "5.1.1	检查是否禁止root用户远程telnet登录	重要	自行判断	参考父项5.1	参考《Linux系统安全配置基线》对应章节	$stelnet	TRUE		" >> "$csvFile"
#	print_pass
#else
#	echo "5.1.1	检查是否禁止root用户远程telnet登录	重要	自行判断	参考父项5.1	参考《Linux系统安全配置基线》对应章节	$stelnet	FAIL		" >> "$csvFile"
#	flag4=0
#	print_fail
#fi


#print_info "检查是否禁止root用户远程ssh登录"
#ssh=`cat /etc/ssh/sshd_config | grep PermitRootLogin | grep no | grep -v ^#`
#if [ -n "$ssh" ]; then
#	echo "5.1.2	检查是否禁止root用户远程ssh登录	重要	自行判断	参考父项5.1	参考《Linux系统安全配置基线》对应章节	$ssh	TRUE		" >> "$csvFile"
#	print_pass
#else
#	echo "5.1.2	检查是否禁止root用户远程ssh登录	重要	自行判断	参考父项5.1	参考《Linux系统安全配置基线》对应章节	$ssh	FAIL		" >> "$csvFile"
#	flag4=0
#	print_fail
#fi


#if [ "$flag4" -eq 1 ]; then
#	pass=$(($pass+1))
#else
#	fail=$(($fail+1))
#fi

#print_dot_line



#
check_point="协议安全-5.1:检查系统openssh安全配置"
index=$(($index+1))
print_check_point $index "$check_point"
Protocol=`cat /etc/ssh/sshd_config | grep -i Protocol | egrep -v ^\# | awk '{print $2}'`
#PermitRootLogin=`cat /etc/ssh/sshd_config | grep -i PermitRootLogin | egrep -v ^\# | awk '{print $2}'`
#print_info "'PermitRootLogin 为no 且 Protocol 为2'"
print_info "'Protocol 为2'"
print_info "/etc/ssh/sshd_config 两项配置如下:"
#print_info 'PermitRootLogin ==> '"[ $PermitRootLogin ]"
print_info 'Protocol ==> '"[ $Protocol ]"
#if [ "$PermitRootLogin" = "no" ] && [ "$Protocol" -eq 2 ]; then
if [ "$Protocol" -eq 2 ]; then
  pass=$(($pass+1))
  print_pass
echo "5.1	检查系统openssh安全配置	一般	建议调整	openssh是使用加密的远程登录实现，可以有效保护登录及数据的安全。此检查项建议调整	2	$Protocol	TRUE		" >> "$csvFile"
else
	echo "5.1	检查系统openssh安全配置	一般	建议调整	openssh是使用加密的远程登录实现，可以有效保护登录及数据的安全。此检查项建议调整	2	$Protocol	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi

print_dot_line

check_point="协议安全-5.2:检查是否修改SNMP默认团体字"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'如果没有必要，需要停止SNMP服务，如果确实需要使用SNMP服务，需要修改SNMP默认团体字'"

snmp=`ps -ef|grep "snmpd"|grep -v "grep"`
if [ -z "$snmp" ]; then
  print_info "SNMP Server is not running..."
	echo "5.2	检查是否修改SNMP默认团体字	一般	建议调整	snmp的默认团体字存在安全漏洞，容易导致服务器信息泄漏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$snmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
  string=`cat /etc/snmp/snmpd.conf | grep com2sec  | grep public | grep -v ^# `
  if [ -n "$string" ]; then
	echo "5.2	检查是否修改SNMP默认团体字	一般	建议调整	snmp的默认团体字存在安全漏洞，容易导致服务器信息泄漏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$snmp	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  else
	echo "5.2	检查是否修改SNMP默认团体字	一般	建议调整	snmp的默认团体字存在安全漏洞，容易导致服务器信息泄漏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$snmp	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  fi
fi
print_dot_line

check_point="协议安全-5.3:检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议'"

msg="1.在网站上免费获取OpenSSH http://www.openssh.com/，并根据安装文件说明执行安装步骤
在/etc/services文件中，注释掉 telnet 23/tcp 一行(如不生效重启telnetd服务或xinetd服务或系统，例如，Red Hat 上重启xinetd：service xinetd restart，根据实际情况操作)"
print_info "$msg"
manual=$(($manual+1))
echo "5.3	检查使用ip协议远程维护的设备是否配置ssh协议，禁用telnet协议	重要	建议调整	Telnet协议名文传输，安全性低，容易被嗅探泄漏信息。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line

check_point="协议安全-5.4:检查是否禁止root用户登录FTP"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'FTP服务未运行 或 root被禁用'"

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
  print_info "No FTP Service"
	echo "5.4	检查是否禁止root用户登录FTP	一般	建议调整	由于root用户权限过大，容易导致系统文件误删除。此检查项建议调整	null	略	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
  print_info "1.FTP服务正在运行..."
  print_info "2.检查 /etc/vsftpd/ftpusers 配置文件中是否有root，以下是文件内容"
  print_info "`cat /etc/vsftpd/ftpusers`"
  root=`cat /etc/vsftpd/ftpusers | grep root | grep -v ^#`
  if [ -n "$root" ]; then
echo "5.4	检查是否禁止root用户登录FTP	一般	建议调整	由于root用户权限过大，容易导致系统文件误删除。此检查项建议调整	null	略	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  else
	echo "5.4	检查是否禁止root用户登录FTP	一般	建议调整	由于root用户权限过大，容易导致系统文件误删除。此检查项建议调整	null	略	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  fi
fi
print_dot_line


check_point="协议安全-5.5:检查是否禁止匿名用户登录FTP"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'FTP服务未启用或者限制了匿名账号登录ftp服务器则合规'"

tmp=`ps -ef | grep ftp | grep -v grep`
tmp1=`cat /etc/vsftpd/vsftpd.conf`
if [ -z "$tmp" ]; then
	echo "5.5	检查是否禁止匿名用户登录FTP	重要	建议调整	由于匿名用户对被黑客用来进入ftp，导致系统文件的保密性和完整性遭到破坏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  print_info "No FTP Service"
  pass=$(($pass+1))
  print_pass
else
  tmp=`cat /etc/vsftpd/vsftpd.conf | grep "anonymous_enable=NO" | grep -v ^#`
  if [ -z "$tmp" ]; then
    print_info "$tmp"
	echo "5.5	检查是否禁止匿名用户登录FTP	重要	建议调整	由于匿名用户对被黑客用来进入ftp，导致系统文件的保密性和完整性遭到破坏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  else
	echo "5.5	检查是否禁止匿名用户登录FTP	重要	建议调整	由于匿名用户对被黑客用来进入ftp，导致系统文件的保密性和完整性遭到破坏。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  fi
fi
print_dot_line


check_point="其他配置-6.1:检查是否设置命令行界面超时退出"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'命令行界面超时自动登出时间TMOUT应不大于600s'"

TMOUT=`cat /etc/profile |grep -i TMOUT | grep -v ^#`
if [ -z "$TMOUT" ]; then
  print_info "没有设置超时时间TMOUT"
	echo "6.1	检查是否设置命令行界面超时退出	重要	自行判断	根据等保要求，建议设置超时时间不大于600s，此检查项建议系统管理员根据系统情况自行判断	<=600	$TMOUT	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
else
TMOUT=`cat /etc/profile |grep -i TMOUT | egrep -v ^\# | awk -F "=" '{print $2}'`
#echo "$TMOUT"
  if [ "$TMOUT" -gt 600 ]; then
    print_info "TMOUT值过大:""$TMOUT"
	echo "6.1	检查是否设置命令行界面超时退出	重要	自行判断	根据等保要求，建议设置超时时间不大于600s，此检查项建议系统管理员根据系统情况自行判断	<=600	$TMOUT	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  else
    print_info "TMOUT:""$TMOUT"
	echo "6.1	检查是否设置命令行界面超时退出	重要	自行判断	根据等保要求，建议设置超时时间不大于600s，此检查项建议系统管理员根据系统情况自行判断	<=600	$TMOUT	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  fi
fi
print_dot_line



check_point="其他配置-6.2:检查是否设置系统引导管理器密码"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "检查是否设置系统引导管理器密码，grub/lilo"

grub=`cat /boot/grub/menu.lst`
lilo=`cat /etc/lilo.conf`
if [ -n "$grub" ]; then
	print_info "系统引导器为grub！"
	grub_pass=`echo $grub | grep password`
	if [ -n "$grub_pass" ]; then
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	TRUE		" >> "$csvFile"
		pass=$(($pass+1))
		print_pass
	else
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	FAIL		" >> "$csvFile"
		fail=$(($fail+1))
		print_fail
	fi
fi

if [ -n "$lilo" ]; then
	print_info "系统引导器为lilo！"
	lilo_pass=`echo $lilo | grep password`
	if [ -n "$lilo_pass" ]; then
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	TRUE		" >> "$csvFile"
		pass=$(($pass+1))
		print_pass
	else
		echo "6.2	检查是否设置系统引导管理器密码	可选	自行判断	应根据引导器不同类型设置引导管理器密码。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$grub_pass	FAIL		" >> "$csvFile"
		fail=$(($fail+1))
		print_fail
	fi
fi
print_dot_line


check_point="其他配置-6.3:检查系统coredump设置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'core dump中可能包括系统信息，易被入侵者利用，建议关闭'"
print_info "设置* soft  core、* hard core为0，且注释掉ulimit -S -c 0 > /dev/null 2>&1"

soft=`cat /etc/security/limits.conf | grep soft | grep core | grep 0 | grep ^*`
hard=`cat /etc/security/limits.conf | grep hard | grep core | grep 0 | grep ^*`
if [ -z "$soft" ] && [ -z "$hard" ]; then

	echo "6.3	检查系统coredump设置	一般	建议调整	需要检查系统cire dump设置，防止内存状态信息暴露，此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
    	fail=$(($fail+1))
    	print_fail
else
	echo "6.3	检查系统coredump设置	一般	建议调整	需要检查系统cire dump设置，防止内存状态信息暴露，此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
fi
print_dot_line

check_point="其他配置-6.4:检查历史命令设置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'HISTFILESIZE和HISTSIZE的值应小于等于5'"

print_info "实际检测值为:"
HISTSIZE=`cat /etc/profile | grep ^HISTSIZE | egrep -v ^\#`
HISTFILESIZE=`cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\#`
if [ -n "$HISTSIZE" ] && [ -n "$HISTFILESIZE" ]; then
  HISTSIZE=`cat /etc/profile | grep ^HISTSIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  HISTFILESIZE=`cat /etc/profile | grep ^HISTFILESIZE | egrep -v ^\# | awk -F "=" '{print $2}'`
  print_info "HISTSIZE => "" [ $HISTSIZE ]"
  print_info "HISTFILESIZE => "" [ $HISTFILESIZE ]"
  if [ "$HISTSIZE" -le 5 ] && [ "$HISTFILESIZE" -le 5 ]; then
	echo "6.4	检查历史命令设置	可选	建议调整	根据等保要求，需保证历史命令文件HISTSIZE的值修改为5，此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$HISTSIZE，$HISTFILESIZE	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  else
	echo "6.4	检查历史命令设置	可选	建议调整	根据等保要求，需保证历史命令文件HISTSIZE的值修改为5，此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$HISTSIZE，$HISTFILESIZE	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  fi
else
	echo "6.4	检查历史命令设置	可选	建议调整	根据等保要求，需保证历史命令文件HISTSIZE的值修改为5，此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$HISTSIZE，$HISTFILESIZE	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line
check_point="其他配置-6.5:检查是否使用PAM认证模块禁止wheel组之外的用户su为root"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'使用PAM禁止任何人su为root'"
print_info "检查/etc/pam.d/su文件中，是否存在如下配置:"
print_info "auth  sufficient pam_rootok.so"
print_info "auth  required pam_wheel.so group=wheel"

pam_rootok=`cat /etc/pam.d/su | grep auth | grep sufficient | grep pam_rootok.so | grep -v ^#`
pam_wheel=`cat /etc/pam.d/su | grep auth | grep pam_wheel.so | grep group=wheel | grep -v ^#`
print_info "实际配置如下:"
print_info "$pam_rootok"
print_info "$pam_wheel"
if [ -n "$pam_rootok" ] && [ -n "$pam_wheel" ]; then
	echo "6.5	检查是否使用PAM认证模块禁止wheel组之外的用户su为root	重要	建议调整	禁止wheel组外用户使用su命令，提高操作系统的完整性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	略	TRUE		" >> "$csvFile"
  	pass=$(($pass+1))
  	print_pass
else
	echo "6.5	检查是否使用PAM认证模块禁止wheel组之外的用户su为root	重要	建议调整	禁止wheel组外用户使用su命令，提高操作系统的完整性。此检查项建议调整	s参考《Linux系统安全配置基线》对应章节	略	FAIL		" >> "$csvFile"
  	fail=$(($fail+1))
  	print_fail

fi
print_dot_line


check_point="其他配置-6.6:检查是否对系统账户进行登录限制"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "禁止系统账户进行交互式登录！"


msg="请手动检查文件文件/etc/passwd，/etc/shadow，并使用命令：usermod -s /sbin/nologin username"
print_info "$msg"
manual=$(($manual+1))
echo "6.6	检查是否对系统账户进行登录限制	可选	建议调整	对系统账户登录进行限制，禁止账户交互式登录。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	null	MANUAL  " >> "$csvFile"
print_manual_check
print_dot_line

check_point="其他配置-6.7:检查密码重复使用次数限制"
index=$(($index+1))
print_check_point $index "$check_point"
line=`cat /etc/pam.d/system-auth | grep password | grep sufficient | grep pam_unix.so | grep remember | grep -v ^#`
print_info "'口令重复使用限制次数 remember >=5'"

print_info "[ $line ]"
if [ -n "$line" ]; then
  times=`echo $line|awk -F "remember=" '{print $2}'`
  if [ $times -ge 5 ]; then
	echo "6.7	检查密码重复使用次数限制	一般	建议调整	检测密码重复使用次数，预防密码重复使用被爆破的风险。此检查项建议调整	>=5	$times	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  else
	echo "6.7	检查密码重复使用次数限制	一般	建议调整	检测密码重复使用次数，预防密码重复使用被爆破的风险。此检查项建议调整	>=5	$times	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  fi
else
	echo "6.7	检查密码重复使用次数限制	一般	建议调整	检测密码重复使用次数，预防密码重复使用被爆破的风险。此检查项建议调整	>=5	$times	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line


check_point="其他配置-6.8:检查账户认证失败次数限制"
index=$(($index+1))
print_check_point $index "$check_point"

print_info "登录失败限制可以使用pam_tally或pam.d，请手工检测/etc/pam.d/system-auth"
manual=$(($manual+1))
echo "6.8	检查账户认证失败次数限制	可选	建议调整	应配置密码失败次数限制，预防密码被爆破的风险。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line


check_point="其他配置-6.9:检查是否关闭绑定多ip功能"
echo "6.9	检查是否关闭ip伪装和绑定多ip功能	可选	建议调整	应关闭此条检查项配置内容，使系统操作责任到人。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	参考子项	参考子项		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_dot_line
flag5=1
#print_info "检查是否配置关闭ip伪装"
#nospoof=`cat /etc/host.conf | grep nospoof`
#if [ -n "$nospoof" ]; then
#	nospoof1=`echo $nospoof | grep on`
#	if [ -n "$nospoof1" ]; then
#		echo "6.9.1	检查是否配置关闭ip伪装	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$nospoof1	TRUE		" >> "$csvFile"
#		print_pass
#	else
#		echo "6.9.1	检查是否配置关闭ip伪装	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$nospoof1	FAIL		" >> "$csvFile"
#		flag5=0
#		print_fail
#	fi
#else
#	echo "6.9.1	检查是否配置关闭ip伪装	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$nospoof	FAIL		" >> "$csvFile"
#	flag5=0
#	print_fail
#fi

print_info "检查是否关闭多ip绑定"
multi=`cat /etc/host.conf | grep multi`
if [ -n "$multi" ]; then
	multi1=`echo $multi | grep off`
	if [ -n "$multi1" ]; then
		echo "6.9.1	检查是否关闭多ip绑定	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$multi1	TRUE		" >> "$csvFile"
		print_pass
	else
		echo "6.9.1	检查是否关闭多ip绑定	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$multi1	FAIL		" >> "$csvFile"
		flag5=0
		print_fail
	fi
else
	echo "6.9.1	检查是否关闭多ip绑定	可选	建议调整	参考父项6.9	参考《Linux系统安全配置基线》对应章节	$multi	FAIL		" >> "$csvFile"
	flag5=0
	print_fail
fi
if [ "$flag5" -eq 1 ]; then
	pass=$(($pass+1))
else
	fail=$(($fail+1))
fi
print_dot_line



check_point="其他配置-6.10:检查是否限制远程登录IP范围"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'设备应支持对允许登录到该设备的IP地址范围进行设定'"

print_info "请手工查看/etc/hosts.allow和/etc/hosts.deny两个文件"
manual=$(($manual+1))
echo "6.10	检查是否限制远程登录IP范围	可选	自行判断	应配置相关设置防止未知ip远程登录，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line

check_point="其他配置-6.11:检查别名文件/etc/aliase"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查是否配合配置了ls和rm命令别名'"

#aol=`cat  ~/.bashrc | grep "^alias ls='ls -aol'"`
#rmi=`cat  ~/.bashrc | grep "^alias rm='rm -i"`
#print_info "aol ==> "" [ $aol ]"
#print_info "rmi ==> "" [ $rmi ]"
#if [ -n "$aol" ] && [ -n "$rmi" ]; then
#	echo "6.11	检查别名文件/etc/aliase	可选	自行判断	/etc/aliases是linux系统下的一种配置文件，作用是将使用者名称进行转换，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$aol，$rmi	TRUE		" >> "$csvFile"
 # pass=$(($pass+1))
  #print_pass
#else
#	echo "6.11	检查别名文件/etc/aliase	可选	自行判断	/etc/aliases是linux系统下的一种配置文件，作用是将使用者名称进行转换，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$aol，$rmi	FAIL		" >> "$csvFile"
 # fail=$(($fail+1))
  #print_fail
#fi
#print_dot_line

echo "6.11	检查别名文件/etc/aliases	可选	自行判断	/etc/aliases是linux系统下的一种配置文件，作用是将使用者名称进行转换，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"



check_point="其他配置-6.12:检查拥有suid和sgid权限的文件"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查重要文件是否存在suid和sgid权限'"

find=`find /usr/bin/chage /usr/bin/gpasswd /usr/bin/wall /usr/bin/chfn /usr/bin/chsh /usr/bin/newgrp /usr/bin/write /usr/sbin/usernetctl /usr/sbin/traceroute /bin/mount /bin/umount /bin/ping /sbin/netreport -type f -perm +6000 2>/dev/null`
if [ -n "$find" ]; then
	print_info "拥有suid和sgid的文件如下："
	print_info "$find"
	print_info "可以使用如：chmod a-s /usr/bin/change命令修改"
	echo "6.12	检查拥有suid和sgid权限的文件	可选	建议调整	suid的管理上有漏洞，易被黑客利用suid来踢拳，来放后门控制linux主机。此检查项建议调整	$dind		FAIL		" >> "$csvFile"
	fail=$(($fail+1))
	print_fail
else
	echo "6.12	检查拥有suid和sgid权限的文件	可选	建议调整	suid的管理上有漏洞，易被黑客利用suid来踢拳，来放后门控制linux主机。此检查项建议调整	$dind		TRUE		" >> "$csvFile"
	pass=$(($pass+1))
	print_pass
fi
print_dot_line


check_point="其他配置-6.13:检查是否配置定时自动屏幕锁定（适用于图形化界面）"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查是否配置定时自动屏幕锁定（适用于图形化界面）'"

print_info "该检查适用于具有图形化界面检查，具体检查步骤请参考《linux系统安全配置基线-豪森》6.13"
manual=$(($manual+1))
echo "6.13	检查是否配置定时自动屏幕锁定(适用于图形化界面)	可选	建议调整	对具有图形化界面的设备应配置定时自动屏幕锁定。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line

#check_point="其他配置-6.14:检查是否安装chkrootkit进行系统监测"
#index=$(($index+1))
#print_check_point $index "$check_point"
#print_info "'安装入侵检测攻击检查Linux系统是否遭受攻击'"

#chkrootkit=`rpm -qa|grep -i "chkrootkit"`
#print_info "chkrootkit ==> "" [ $chkrootkit ]"
#if [ -n "$chkrootkit" ]; then
#	echo "6.14	检查是否安装chkrootkit进行系统监测	可选	自行判断	Chkrootkit工具是为了检测后门的一款程序，可视情况来确定是否安装，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$chkrootkit	TRUE		" >> "$csvFile"
 # pass=$(($pass+1))
 # print_pass
#else
#	echo "6.14	检查是否安装chkrootkit进行系统监测	可选	自行判断	Chkrootkit工具是为了检测后门的一款程序，可视情况来确定是否安装，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$chkrootkit	FAIL		" >> "$csvFile"
#  fail=$(($fail+1))
#  print_fail
#fi
#print_dot_line


check_point="其他配置-6.14:检查系统内核参数配置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'调整内核安全参数，增强系统安全性，tcp_syncookies的值应设为1'"

tcp_syncookies=`cat /proc/sys/net/ipv4/tcp_syncookies`
print_info "tcp_syncookies ==> "" [ $tcp_syncookies ]"
if [ "$tcp_syncookies" -eq 1 ]; then
	echo "6.14	检查系统内核参数配置	一般	建议调整	该项配置主要为了缓解拒绝服务攻击。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tcp_syncookies	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "6.14	检查系统内核参数配置	一般	建议调整	该项配置主要为了缓解拒绝服务攻击。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tcp_syncookies	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line


check_point="其他配置-6.15:检查是否按组进行账号管理"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查是否按组进行账号管理'"

print_info "请自行检查！具体检查步骤请参考《linux系统安全配置基线-豪森》6.15"
manual=$(($manual+1))
echo "6.15	检查是否按组进行账号管理	可选	自行判断	该项配置主要偏向于对系统用户的管理，如账户已分组管理，该检查项可以跳过。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line

check_point="其他配置-6.16:检查是否按用户分配账号"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查是否按用户分配账号'"

print_info "请自行检查！具体检查步骤请参考《linux系统安全配置基线-豪森》6.16"
manual=$(($manual+1))
echo "6.16	检查是否按用户分配账号	可选	自行判断	该项配置主要偏向于对系统用户的管理，如有未知账号，清及时调整与关闭。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
print_manual_check
print_dot_line

check_point="其他配置-6.17:检查root用户的path环境变量"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'PATH环境变量中不存在.或者..的路径(此处以不存在'..'为检查条件，因为'.'可能会存在于软件版本号中)'"

print_info "PATH环境变量如下:"
tmp=`echo $PATH | egrep '\.\.'`
print_info "$PATH"
if [ -z "$tmp" ]; then
	echo "6.17	检查root用户的path环境变量	一般	建议调整	如果将（.和..）这来两者写入root的环境变量，执行脚本时，输入脚本名字后，系统会在当前的目录下执行该脚本，如脚本有危险命令，将会对系统造成较大影响。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "6.17	检查root用户的path环境变量	一般	建议调整	如果将（.和..）这来两者写入root的环境变量，执行脚本时，输入脚本名字后，系统会在当前的目录下执行该脚本，如脚本有危险命令，将会对系统造成较大影响。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="其他配置-6.18:检查系统是否禁用Ctrl+Alt+Delete组合键"
index=$(($index+1))
print_check_point $index "$check_point"
tmp=`cat /usr/lib/systemd/system/ctrl-alt-del.target | grep "Alias=ctrl-alt-del.target" | grep -v ^#`
print_info "'应禁用Ctrl+Alt+Delete组合键重启系统'"

print_info "Ctrl+Alt+Delete的配置如下:"
print_info $tmp
if [ -n "$tmp" ]; then
	echo "6.18	检查系统是否禁用Ctrl+Alt+Delete组合键	一般	建议调整	linux操作系统只要按下Ctrl+Alt+Del快捷键，系统有时会重启。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
else
	echo "6.18	检查系统是否禁用Ctrl+Alt+Delete组合键	一般	建议调整	linux操作系统只要按下Ctrl+Alt+Del快捷键，系统有时会重启。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
fi
print_dot_line


check_point="其他配置-6.19:检查系统是否关闭系统信任机制"
echo "6.19	检查系统是否关闭系统信任机制	重要	建议调整	如不关闭系统信任机制，在信任地址列表中的来访用户可不用提供口令就在本地计算机上执行远程命令。此检查项建议调整	=0	参考子项	参考子项		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查系统是否关闭系统信任机制'"

equiv=`find / -maxdepth 2 -name hosts.equiv`
rhosts=`find / -maxdepth 3 -type f -name .rhosts 2>/dev/null`
print_info "检查是否存在equiv文件"
if [ -n "$equiv" ]; then
	echo "6.19.1	检查是否存在equiv文件	重要	建议调整	参考父项6.19	参考《Linux系统安全配置基线》对应章节	$equiv	FAIL		" >> "$csvFile"
	fail=$(($fail+1))
	print_fail
else
	echo "6.19.1	检查是否存在equiv文件	重要	建议调整	参考父项6.19	参考《Linux系统安全配置基线》对应章节	$equiv	TRUE		" >> "$csvFile"
	pass=$(($pass+1))
	print_pass
fi

print_info "检查是否存在rhosts文件"
if [ -n "$rhosts" ]; then
	echo "6.19.2	检查是否存在rhosts文件	重要	建议调整	参考父项6.19	参考《Linux系统安全配置基线》对应章节	$rhosts	FAIL		" >> "$csvFile"
	fail=$(($fail+1))
	print_fail
else
	echo "6.19.2	检查是否存在rhosts文件	重要	建议调整	参考父项6.19	参考《Linux系统安全配置基线》对应章节	$rhosts	TRUE		" >> "$csvFile"
	pass=$(($pass+1))
	print_pass
fi

print_dot_line
check_point="其他配置-6.20:检查磁盘空间占用率"

index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查磁盘空间占用率，建议不超过80%'"
print_info "`df -h`"
space=$(df -h | awk -F "[ %]+" 'NR!=1''{print $5}')
flag=0
for i in $space
do
  if [ $i -ge 80 ];then
    flag=1
    print_info "请使用命令手工检查磁盘空间占用率情况"
  fi
done
if [ "$flag" -eq 1 ];then
  manual=$(($manual+1))
  echo "6.20	检查磁盘空间占用率	可选	自行判断	磁盘动态分区空间不足，可能会导致系统卡慢与崩溃。此检查项建议系统管理员根据系统情况自行判断	<=80	null	MANUAL		" >> "$csvFile"
  print_manual_check
else
  pass=$(($pass+1))
  echo "6.20	检查磁盘空间占用率	可选	自行判断	磁盘动态分区空间不足，可能会导致系统卡慢与崩溃。此检查项建议系统管理员根据系统情况自行判断	<=80	略	TRUE		" >> "$csvFile"
  print_pass
fi
print_dot_line


check_point="其他配置-6.21:检查是否删除了潜在危险文件"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'系统不应该存在.rhost、.netrc、hosts.equiv这三个文件则合规'"

rhost=`locate .rhost | egrep 'rhost$'`
equiv=`locate .netrc | egrep 'netrc$'`
equiv=`locate .equiv | egrep 'hosts.equiv$'`
print_info "rhost ==> "" [ $rhost ]"
print_info "netrc ==> "" [ $netrc ]"
print_info "equiv ==> "" [ $equiv ]"
if [ -z "$rhost" ] && [ -z "$netrc" ] && [ -z "$equiv" ]; then
	echo "6.21	检查是否删除了潜在危险文件	重要	建议调整	危险文件为删除可能导致用户无口令登录系统，存在较大风险。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$rhost，$netrc，$equiv	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "6.21	检查是否删除了潜在危险文件	重要	建议调整	危险文件为删除可能导致用户无口令登录系统，存在较大风险。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$rhost，$netrc，$equiv	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="其他配置-6.22:检查是否删除与设备运行，维护等工作无关的账号"
echo "6.22	检查是否删除与设备运行，维护等工作无关的账号	可选	建议调整	该项配置主要偏向于对系统用户的管理，如有未知账号，请及时关闭。此项建议整改	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'检查是否删除与设备运行，维护等工作无关的账号'"

print_info "请手工检查！具体检查步骤请参考《linux系统安全配置基线-豪森》6.22"
print_dot_line

check_point="其他配置-6.23:检查是否配置用户所需最小权限"
index=$(($index+1))
print_check_point $index "$check_point"
passwd=`stat -c %a /etc/passwd`
shadow=`stat -c %a /etc/shadow`
group=`stat -c %a /etc/group`
print_info "'在设备权限配置能力内，根据用户的业务需要，配置其所需的最小权限'"
print_info "建议文件权限:(不大于左侧值)"
print_info "644 /etc/passwd"
print_info "400 /etc/shadow"
print_info "644 /etc/group"

print_info "实际检测值为:"
print_info "$passwd"" /etc/passwd"
print_info "$shadow"" /etc/shadow"
print_info "$group"" /etc/group"
if [ "$passwd" -le 644 ] && [ "$shadow" -le 400 ] && [ "$group" -le 644 ]; then
	echo "6.23	检查是否配置用户所需最小权限	一般	建议调整	权限配置应为满足使用场景的最小化权限。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$passwd，$shadow，$group	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
print_pass
else
	echo "6.23	检查是否配置用户所需最小权限	一般	建议调整	权限配置应为满足使用场景的最小化权限。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$passwd，$shadow，$group	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
print_fail
fi
print_dot_line


check_point="其他配置-6.24:检查是否关闭数据包转发功能"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'对于不做路由功能的系统，应该关闭数据包转发功能'"

ip_forward=`sysctl -n net.ipv4.ip_forward`
print_info "实际值 ==> ip_forward:"" [ $ip_forward ] "
if [ 0 -eq "$ip_forward" ]; then
	echo "6.24	检查是否关闭数据包转发功能	可选	自行判断	Linux系统默认是禁止数据包转发的，如非系统需要，请关闭该功能。此检查项建议系统管理员根据系统情况自行判断	=0	$ip_forward	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
	echo "6.24	检查是否关闭数据包转发功能	可选	自行判断	Linux系统默认是禁止数据包转发的，如非系统需要，请关闭该功能。此检查项建议系统管理员根据系统情况自行判断	=0	$ip_forward	FAIL		" >> "$csvFile"
  fail=$(($fail+1))
  print_fail
fi
print_dot_line

check_point="其他配置-6.25:检查是否关闭不必要的服务和端口"
echo "6.25	检查是否关闭不必要的服务和端口	可选	自行判断	不必要的服务会消耗系统内存，且存在安全隐患，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'结合实际业务需要人工判断是否存在不必要的未关闭的端口和服务，请通过以下命令，手工检查'"

print_info "# chkconfig --list"
manual=$(($manual+1))
print_manual_check
print_dot_line

check_point="其他配置-6.26:检查是否使用NTP（网络时间协议）保持时间同步"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'如果网络中存在信任的NTP服务器，应该配置系统使用NTP服务保持时间同步。若未开启则不做该配置'"

print_info "NTP服务运行状态信息："
ntpd=`ps -ef|egrep "ntp|ntpd"|grep -v grep | grep "/usr/sbin/ntpd"`
print_info "$ntpd"
if [ -n "$ntpd" ]; then
  server=`cat /etc/ntp.conf | grep ^server`
  print_info "==> servers <=="
  print_info "$server"
  if [ -n "$server" ]; then
	echo "6.26	检查是否使用NTP(网络时间协议)保持时间同步	可选 建议调整	应保证windows系统的时间同步，提高系统日志的准确性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$server	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  else
	echo "6.26	检查是否使用NTP(网络时间协议)保持时间同步	可选 建议调整	应保证windows系统的时间同步，提高系统日志的准确性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$server	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  fi
else
	echo "6.26	检查是否使用NTP(网络时间协议)保持时间同步	可选 建议调整	应保证windows系统的时间同步，提高系统日志的准确性。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$server	TRUE		" >> "$csvFile"
  print_info "==> NTP Service is not running..."
  pass=$(($pass+1))
  print_pass
fi
print_dot_line

check_point="其他配置-6.27:检查NFS（网络文件系统）服务配置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'如果没有必要，需要停止NFS服务；如果需要NFS服务，需要限制能够访问NFS服务的IP范围'"

tmp=`netstat -lntp | grep nfs`
if [ -z "$tmp" ]; then
	echo "6.27	检查NFS(网络文件系统)服务配置	可选	自行判断	如果需要NFS服务，需要限制能够访问NFS服务的IP范围，如果没有必要，需要停止NFS服务。此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  print_info "NFS 服务未启用..."
  pass=$(($pass+1))
  print_pass
else
  allow=`cat /etc/hosts.allow | grep -v ^#`
  deny=`cat /etc/hosts.deny | grep -v ^#`
  if [ -n "$allow" ] && [ -n "$deny" ]; then
	echo "6.27 检查NFS(网络文件系统)服务配置 TRUE" >> "$csvFile"
    print_info "hosts.allow 和 hosts.deny皆已配置"
    pass=$(($pass+1))
    print_pass
  else
	echo "6.27 检查NFS(网络文件系统)服务配置 FAIL" >> "$csvFile"
    print_info "未配置hosts.allow 或 hosts.deny"
    fail=$(($fail+1))
    print_fail
  fi
fi
print_dot_line

check_point="其他配置-6.28:检查是否安装OS补丁"
echo "6.28	检查是否安装OS补丁	可选	自行判断	及时安装操作系统补丁保证系统稳定性，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	null	MANUAL		" >> "$csvFile"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'手工检查当前系统版本是否安装最新补丁'"

os=`uname -a`
print_info "==> please manual check os version ..."
print_info "$os"
manual=$(($manual+1))
print_manual_check
print_dot_line

check_point="其他配置-6.29:检查是否设置SSH成功登录后Banner"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'用户通过网络或者本地成功登录系统后，显示一些警告信息'"

#systemctl is centos7 or redhat 7 
#tmp=`systemctl status sshd | grep running`
tmp=`service sshd status | grep running`
if [ -z "$tmp" ]; then
  print_info "==>SSHD is not running..."
	echo "6.29	检查是否设置SSH成功登录后Banner	可选	建议调整	检查是否设置ssh成功登录后的Banner信息，提示登录系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
  temp=`cat /etc/motd`
  if [ -n "$temp" ]; then
	echo "6.29	检查是否设置SSH成功登录后Banner	可选	建议调整	检查是否设置ssh成功登录后的Banner信息，提示登录系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	MANUAL		" >> "$csvFile"
    print_info "请手工检查/etc/motd文件中的内容是否符合要求"
    print_info "$temp"
    manual=$(($manual+1))
    print_manual_check
  else
    print_info "/etc/motd文件中内容为空，不提示登录信息"
	echo "6.29	检查是否设置SSH成功登录后Banner	可选	建议调整	检查是否设置ssh成功登录后的Banner信息，提示登录系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  fi
fi
print_dot_line

#check_point="其他配置-6.30:检查日志文件权限设置"
#index=$(($index+1))
#print_check_point $index "$check_point"
#messages=`stat -c %a /var/log/messages`
#dmesg=`stat -c %a /var/log/dmesg`
#maillog=`stat -c %a /var/log/maillog`
#secure=`stat -c %a /var/log/secure`
#wtmp=`stat -c %a /var/log/wtmp`
#cron=`stat -c %a /var/log/cron`
#print_info "'设备应配置权限，控制对日志文件读取、修改和删除等操作'"
#print_info "推荐的文件权限:(不大于左侧值)"
#print_info "600 /var/log/messages"
#print_info "600 /var/log/secure、"
#print_info "600 /var/log/maillog、"
#print_info "600 /var/log/cron"
#print_info "644 /var/log/dmesg"
#print_info "664 /var/log/wtmp"

#print_info "目前的文件权限如下:"
#print_info $messages' /var/log/messages'
#print_info $dmesg' /var/log/dmesg  '
#print_info $maillog' /var/log/maillog  '
#print_info $secure' /var/log/secure  '
#print_info $wtmp' /var/log/wtmp  '
#print_info $cron' /var/log/cron  '
#if [ "$messages" -le 600 ] && [ "$secure" -le 600 ] && [ "$maillog" -le 600 ] && [ "$cron" -le 600 ] && [ "$dmesg" -le 644 ] && [ "$wtmp" -le 664 ]; then
 # pass=$(($pass+1))
#echo "6.30	检查日志文件权限设置	可选	建议调整	徐检查日志文件权限设置，保证同组用户、其他组用户不得有写入、执行权限。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$messages，$secure，$maillog，$cron，$dmesg，$wtmp	TRUE		" >> "$csvFile"
 # print_pass
#else
	#echo "6.30	检查日志文件权限设置	可选	建议调整	徐检查日志文件权限设置，保证同组用户、其他组用户不得有写入、执行权限。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$messages，$secure，$maillog，$cron，$dmesg，$wtmp	FAIL		" >> "$csvFile"
  #fail=$(($fail+1))
  #print_fail
#fi
#print_dot_line

check_point="其他配置-6.30:检查FTP用户上传的文件所具有的权限"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'FTP服务未运行，或ftp用户和匿名用户上传文件的权限为022'"

tmp=`netstat -lntp | grep ftp`
print_info "$tmp"
if [ -z "$tmp" ]; then
	echo "6.30	检查FTP用户上传的文件所具有的权限	可选	建议调整	限制FTP用户登录后上传文件的属性，保证同组用户、其他用户不得有写入权限。此检查项建议调整	参考《Linux系统安全配置基线》对应要求	$tmp	TRUE		" >> "$csvFile"
  print_info "No FTP Service"
  pass=$(($pass+1))
  print_pass
else
  local_umask=`cat /etc/vsftpd/vsftpd.conf | grep local_umask | grep 022 | grep -v ^#`
  anon_umask=`cat /etc/vsftpd/vsftpd.conf | grep anon_umask | grep 022 | grep -v ^#`
  if [ -n "$local_umask" ] && [ -n "$anon_umask" ]; then
	echo "6.30	检查FTP用户上传的文件所具有的权限	可选	建议调整	限制FTP用户登录后上传文件的属性，保证同组用户、其他用户不得有写入权限。此检查项建议调整	参考《Linux系统安全配置基线》对应要求	$tmp	TRUE		" >> "$csvFile"
    pass=$(($pass+1))
    print_pass
  else
	echo "6.30	检查FTP用户上传的文件所具有的权限	可选	建议调整	限制FTP用户登录后上传文件的属性，保证同组用户、其他用户不得有写入权限。此检查项建议调整	参考《Linux系统安全配置基线》对应要求	$tmp	FAIL		" >> "$csvFile"
    print_info 'local_umask:'"[ $local_umask ]"
    print_info 'anon_umask:'"[ $anon_umask ]"
    fail=$(($fail+1))
    print_fail
  fi
fi
print_dot_line

check_point="其他配置-6.31:检查FTP banner设置"
index=$(($index+1))
print_check_point $index "$check_point"

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
	echo "6.31	检查FTPbanner设置	可选	建议调整	检查是否设置ftp成功登录后的Banner信息，提示登录系统人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	略	TRUE		" >> "$csvFile"
  print_info "FTP Service is not Running..."
  pass=$(($pass+1))
  print_pass
else
	echo "6.31	检查FTPbanner设置	可选	建议调整	检查是否设置ftp成功登录后的Banner信息，提示登录系统人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	略	MANUAL		" >> "$csvFile"
  print_info "请手工检查/etc/vsftpd/vsftpd.conf文件中的banner是否符合要求"
  manual=$(($manual+1))
  print_manual_check
fi
print_dot_line


check_point="其他配置-6.32:检查/usr/bin/目录下可执行文件的拥有者属性"
index=$(($index+1))
print_check_point $index "$check_point"

find=`find /usr/bin -type f \( -perm -04000 -o -perm -02000 \) -exec ls -lg {} \; `
if [ -n "$find" ]; then
	echo "6.32	检查/usr/bin/目录下可执行文件的拥有者属性	可选	建议调整	可执行文件拥有s属性在运行时可所以获得拥有者的权限，所以为了安全需要，需要作出修改。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	略	FAIL		" >> "$csvFile"
	print_info "系统中所有含有“s”属性的文件如下："
	print_info "$find"
	print_info "把不必要的“s”属性去掉，或者把不用的直接删除;# chmod a-s filename"
	fail=$(($fail+1))
	print_fail
else
	echo "6.32	检查/usr/bin/目录下可执行文件的拥有者属性	可选	建议调整	可执行文件拥有s属性在运行时可所以获得拥有者的权限，所以为了安全需要，需要作出修改。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	略	TRUE		" >> "$csvFile"
	pass=$(($pass+1))
	print_pass
fi
print_dot_line

check_point="其他配置-6.33:检查Telnet banner设置"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'FTP登录时需要显示警告信息，隐藏操作系统和FTP服务器相关信息'"


#systemctl是centos7&redhat7
#tmp=`systemctl status telnet.socket  | grep active`
tmp=`service telnet.socket | grep active`
if [ -z "$tmp" ]; then
  print_info "==>Telnet service is not installed or not running..."
  pass=$(($pass+1))
	echo "6.33	检查Telnetbanner设置	可选	建议调整	检查是否设置telnet成功登录后的Banner信息，提示登录系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  print_pass
else
  print_info "Please check /etc/issue、/etc/issue.net whether contains banner information"
  manual=$(($manual+1))
	echo "6.33	检查Telnetbanner设置	可选	建议调整	检查是否设置telnet成功登录后的Banner信息，提示登录系统的人员。此检查项建议调整	参考《Linux系统安全配置基线》对应章节	$tmp	MANUAL		" >> "$csvFile"
  print_manual_check
fi
print_dot_line

check_point="其他配置-6.34:检查是否限制FTP用户登录后能访问的目录"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'FTP服务器应该限制FTP可以使用的目录范围'"

tmp=`ps -ef | grep ftp | grep -v grep`
if [ -z "$tmp" ]; then
  print_info "No FTP Service Running"
	echo "6.34	检查是否限制FTP用户登录后能访问的目录	可选	自行判断	限制FTP用户登录后能访问的目录，防止机密文件非授权访问，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	$tmp	TRUE		" >> "$csvFile"
  pass=$(($pass+1))
  print_pass
else
  chroot_local_user=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_local_user=NO`
  chroot_list_enable=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_enable=YES`
  chroot_list_file=`cat /etc/vsftpd/vsftpd.conf | grep ^chroot_list_file=/etc/vsftpd/chroot_list`
  if [ -n "$chroot_local_user" ] && [ -n "$chroot_list_enable" ] && [ -n "$chroot_list_file" ]; then
    pass=$(($pass+1))
	echo "6.34	检查是否限制FTP用户登录后能访问的目录	可选	自行判断	限制FTP用户登录后能访问的目录，防止机密文件非授权访问，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	略	TRUE		" >> "$csvFile"
    print_pass
  else
	echo "6.34	检查是否限制FTP用户登录后能访问的目录	可选	自行判断	限制FTP用户登录后能访问的目录，防止机密文件非授权访问，此检查项建议系统管理员根据系统情况自行判断	参考《Linux系统安全配置基线》对应章节	略	FAIL		" >> "$csvFile"
    fail=$(($fail+1))
    print_fail
  fi
fi
print_dot_line

check_point="其他配置-6.35:检查是否关闭不必要的服务和端口"
index=$(($index+1))
print_check_point $index "$check_point"
print_info "'结合实际业务需要人工判断是否存在不必要的未关闭的端口和服务，请通过以下命令，手工检查'"

print_info "# chkconfig --list"
chkconfig=`chkconfig --list`
print_info "$chkconfig"
manual=$(($manual+1))
echo "6.35	检查是否关闭不必要的服务和端口	重要	自行判断	不必要的端口和服务会扩大系统的被攻击面，此检查项建议系统管理员根据系统情况自行判断	null	MANUAL		" >> "$csvFile"
print_manual_check


check_point="其他配置-6.36:检查内核版本是否处于CVE-2021-43267漏洞影响版本"
index=$(($index+1))
print_check_point $index "$check_point"
kernel=`uname -r | awk -F- '{ print $1 }' `
kernel1=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $1 }'`
kernel2=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $2 }'`
kernel3=`uname -r | awk -F- '{ print $1 }' | awk -F. '{ print $3 }'`
#5.10-rc1<Linux kernel < 5.14.16
if [ $kernel1 -eq 5 ]; then
	if [ $kernel2 -ge 10 ]&&[ $kernel2 -le 14 ]; then
		if [ $kernel3 -ge 0 ]&&[ $kernel3 -le 16 ]; then
			echo "6.36	检查内核版本是否处于CVE-2021-43267漏洞影响范围	可选	建议调整	CVE-2021-43267漏洞是Linux内核TIPC模块中的一个堆溢出漏洞，攻击者利用该漏洞可以实现本地或远程代码执行漏洞	5.10-rc1<Linux kernel <5.14.16	$kernel	FAIL		" >> "$csvFile"
			print_info "$kernel"
			print_info "该内核范围存在漏洞，请升级内核或打上补丁https://www.kernel.org"
			fail=$(($fail+1))
			print_fail
		else
			echo "6.36	检查内核版本是否处于CVE-2021-43267漏洞影响范围	可选	建议调整	CVE-2021-43267漏洞是Linux内核TIPC模块中的一个堆溢出漏洞，攻击者利用该漏洞可以实现本地或远程代码执行漏洞	5.10-rc1<Linux kernel <5.14.16	$kernel	TRUE		" >> "$csvFile"
			print_info "$kernel"
			pass=$(($pass+1))
			print_pass
		fi

	else
		echo "6.36	检查内核版本是否处于CVE-2021-43267漏洞影响范围	可选	建议调整	CVE-2021-43267漏洞是Linux内核TIPC模块中的一个堆溢出漏洞，攻击者利用该漏洞可以实现本地或远程代码执行漏洞	5.10-rc1<Linux kernel <5.14.16	$kernel	TRUE		" >> "$csvFile"
		print_info "$kernel"
		pass=$(($pass+1))
		print_pass
	fi

else
	echo "6.36	检查内核版本是否处于CVE-2021-43267漏洞影响范围	可选	建议调整	CVE-2021-43267漏洞是Linux内核TIPC模块中的一个堆溢出漏洞，攻击者利用该漏洞可以实现本地或远程代码执行漏洞	5.10-rc1<Linux kernel <5.14.16	$kernel	TRUE		" >> "$csvFile"
	print_info "$kernel"
	pass=$(($pass+1))
	print_pass


fi

print_dot_line
print_check_point "端口信息："
duankou=`netstat -ntlp`
print_info "$duankou"
manual=$(($manual+1))
print_manual_check

print_summary $index $pass $fail $manual

print_dot_line

da=`date`
echo "扫描时间：$da" >> "$csvFile"
echo "$csvFile----->以保存在当前脚本路径"
print_dot_line

iconv -f UTF-8 -t GBK $csvFile -o $csvFile

