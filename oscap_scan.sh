#!/bin/sh

# CHANGE LOG
# ----------
# 2025-04-08  njeffrey  Script created

# NOTES
# -----
# Script to perform regular OpenSCAP scans for CIS compliance
# It is assumed this script runs weekly from the root crontab.  For example:
# 15 4 * * * /root/oscap_reports/oscap_scan.sh  >/dev/null 2>&1  #create report for CIS compliance

# install the openscap packages
yum install openscap-scanner scap-security-guide


# get a list of all profiles in the datastream file, CIS level 1, CIS level 2, HIPAA, DISA STIG, etc
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
oscap info /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml | grep -i CIS


# get more detail about the profile we are interested in, CIS level 1
oscap info --profile xccdf_org.ssgproject.content_profile_cis_server_l1 /usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml

# perform a compliance scan, saving the results to XML and HTML files
test -d /root/openscap_reports || mkdir -p /root/openscap_reports
timestamp=`date +%Y%m%d%H%M`
scap_profile=xccdf_org.ssgproject.content_profile_cis_server_l1
xml_file=/root/openscap_reports/scan_results.$timestamp.xml
html_file=/root/openscap_reports/scan_report.$timestamp.html
datastream_file=/usr/share/xml/scap/ssg/content/ssg-rhel8-ds.xml
oscap xccdf eval --profile $scap_profile --results $xml_file --report $html_file $datastream_file
