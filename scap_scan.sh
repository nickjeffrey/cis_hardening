#!/bin/sh

# CHANGE LOG
# ----------
# 2025-04-08  njeffrey  Script created at https://github.com/nickjeffrey/cis_hardening
# 2025-04-09  njeffrey  Add support for RHEL8, RHEL9, RHEL10
# 2025-09-30  njeffrey  Add support for Oracle Linux 9

# NOTES
# -----
# Script to perform regular OpenSCAP scans for CIS compliance
# It is assumed this script runs weekly from the root crontab.  For example:
# 15 4 * * * /root/scap_reports/scap_scan.sh  >/dev/null 2>&1  #create report for CIS compliance


# install the openscap packages
if [ -f /bin/yum ]; then
   yum -y install openscap-scanner scap-security-guide
   yum -y install ansible-core
fi
if [ -f /bin/apt ]; then
   apt -y install openscap-scanner 
   apt -y install ssg-base ssg-debderived ssg-debian ssg-nondebian ssg-applications
   apt -y install ansible-core
fi


# declare variables
output_dir=/root/scap_reports
timestamp=`date +%Y%m%d%H%M`
host_name=`hostname`
scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1  #RHEL
scap_profile=xccdf_org.ssgproject.content_profile_standard       #Oracle Linux
results_file=$output_dir/scan_results.$host_name_$timestamp.xml
report_file=$output_dir/scan_report.$host_name.$timestamp.html
ansible_playbook=$output_dir/remediation_tasks.$host_name.$timestamp.yml


# confirm the output directory exists
test -d   $output_dir || mkdir -p $output_dir
if [ ! -d $output_dir ]; then
   echo ERROR: cannot create output directory $output_dir
   exit 1
fi


# get a list of all profiles in the datastream file, CIS level 1, CIS level 2, HIPAA, DISA STIG, etc
# Figure out which datastream file to use 
datastream_file="unknown"
cat /etc/os-release | grep PRETTY_NAME | grep "Debian GNU/Linux 11"         && datastream_file=/usr/share/xml/scap/ssg/content/ssg-debian11-ds.xml   && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Debian GNU/Linux 12"         && datastream_file=/usr/share/xml/scap/ssg/content/ssg-debian12-ds.xml   && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Ubuntu 24.04"                && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ubuntu2404-ds.xml && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Ubuntu 26.04"                && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ubuntu2604-ds.xml && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Ubuntu 28.04"                && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ubuntu2804-ds.xml && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "CentOS Stream 8"             && datastream_file=/usr/share/xml/scap/ssg/content/ssg-cs8-ds.xml        && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "CentOS Stream 9"             && datastream_file=/usr/share/xml/scap/ssg/content/ssg-cs9-ds.xml        && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "CentOS Stream 10"            && datastream_file=/usr/share/xml/scap/ssg/content/ssg-cs10-ds.xml       && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "CentOS Stream 11"            && datastream_file=/usr/share/xml/scap/ssg/content/ssg-cs11-ds.xml       && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "CentOS Stream 12"            && datastream_file=/usr/share/xml/scap/ssg/content/ssg-cs12-ds.xml       && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Red Hat Enterprise Linux 8"  && datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml      && scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1 
cat /etc/os-release | grep PRETTY_NAME | grep "Red Hat Enterprise Linux 9"  && datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel9-ds.xml      && scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1 
cat /etc/os-release | grep PRETTY_NAME | grep "Red Hat Enterprise Linux 10" && datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel10-ds.xml     && scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1  
cat /etc/os-release | grep PRETTY_NAME | grep "Red Hat Enterprise Linux 11" && datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel11-ds.xml     && scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1 
cat /etc/os-release | grep PRETTY_NAME | grep "Red Hat Enterprise Linux 12" && datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel12-ds.xml     && scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1  
cat /etc/os-release | grep PRETTY_NAME | grep "Fedora"                      && datastream_file=/usr/share/xml/scap/ssg/content/ssg-fedora-ds.xml     && scap_profile=unknown 
cat /etc/os-release | grep PRETTY_NAME | grep "Oracle Linux Server 8"       && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ol8-ds.xml        && scap_profile=xccdf_org.ssgproject.content_profile_standard 
cat /etc/os-release | grep PRETTY_NAME | grep "Oracle Linux Server 9"       && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ol9-ds.xml        && scap_profile=xccdf_org.ssgproject.content_profile_standard 
cat /etc/os-release | grep PRETTY_NAME | grep "Oracle Linux Server 10"      && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ol10-ds.xml       && scap_profile=xccdf_org.ssgproject.content_profile_standard 
cat /etc/os-release | grep PRETTY_NAME | grep "Oracle Linux Server 11"      && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ol11-ds.xml       && scap_profile=xccdf_org.ssgproject.content_profile_standard  
cat /etc/os-release | grep PRETTY_NAME | grep "Oracle Linux Server 12"      && datastream_file=/usr/share/xml/scap/ssg/content/ssg-ol12-ds.xml       && scap_profile=xccdf_org.ssgproject.content_profile_standard 
#
# Confirm a datastream file was found
if [ ! -f "$datastream_file" ]; then
   echo ERROR: cannot find datastream file
   exit 1
fi
echo Using datastream file $datastream_file


# Get the list of profiles from the appropriate datastream file
# Some linux distros like OL9 need the --fetch-remote-resources flag because the details are kept online
#oscap info $datastream_file
#oscap info $datastream_file | grep -i CIS
oscap info --fetch-remote-resources $datastream_file


# confirm the SCAP profile exists in the datastream file
if [ "$(grep -c $scap_profile $datastream_file)" -eq 0 ]; then
    echo "Error: Could not find SCAP profile $scap_profile in datastream file $datastream_file" >&2
    exit 1
fi


# get more detail about the profile we are interested in (CIS level 1 for RHEL, the OL equivalent is 
oscap info --fetch-remote-resources --profile $scap_profile $datastream_file

# sample output from above command
 Title: Standard System Security Profile for Oracle Linux 9   Id: xccdf_org.ssgproject.content_profile_standard


# perform a compliance scan, saving the results to XML results file and HTML report file
oscap xccdf eval --profile $scap_profile --results $results_file --report $report_file $datastream_file


# generate an ansible playboook that can be optionally used to remediate any issues found
oscap xccdf generate fix --fix-type ansible --output $ansible_playbook --result-id "" $results_file


# tell the sysadmin what has happened
echo "A user-friendly report has been written to $report_file"
echo "Results have been written to XML file $results_file"
echo "Optional remediation tasks have been written to ansible playbook $ansible_playbook"
echo "If you wish to remediate the issues found in the HTML report, please execute:"
echo "   ansible-playbook -i \"localhost,\" -c local $ansible_playbook"

