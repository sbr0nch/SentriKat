#!/usr/bin/env python3
"""
Seed service catalog with 250+ real-world software/services
Services are matched to CVE naming conventions for accurate vulnerability matching
"""

import sys
import os
import json

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app, db
from app.models import ServiceCatalog

# Comprehensive service catalog organized by category
SERVICE_CATALOG = [
    # Containerization & Orchestration
    {'vendor': 'Docker', 'product_name': 'Docker', 'category': 'Containerization', 'subcategory': 'Container Runtime',
     'common_names': json.dumps(['docker', 'docker-ce', 'docker-engine']), 'cpe_vendor': 'docker', 'cpe_product': 'docker',
     'description': 'Container platform', 'website_url': 'https://www.docker.com',
     'typical_versions': json.dumps(['20.10.x', '23.0.x', '24.0.x']), 'is_popular': True},

    {'vendor': 'Kubernetes', 'product_name': 'Kubernetes', 'category': 'Orchestration', 'subcategory': 'Container Orchestration',
     'common_names': json.dumps(['kubernetes', 'k8s', 'kube']), 'cpe_vendor': 'kubernetes', 'cpe_product': 'kubernetes',
     'description': 'Container orchestration platform', 'website_url': 'https://kubernetes.io',
     'typical_versions': json.dumps(['1.26.x', '1.27.x', '1.28.x', '1.29.x']), 'is_popular': True},

    {'vendor': 'Red Hat', 'product_name': 'Podman', 'category': 'Containerization', 'subcategory': 'Container Runtime',
     'common_names': json.dumps(['podman']), 'cpe_vendor': 'redhat', 'cpe_product': 'podman',
     'description': 'Daemonless container engine', 'website_url': 'https://podman.io',
     'typical_versions': json.dumps(['4.x', '5.x']), 'is_popular': False},

    {'vendor': 'containerd', 'product_name': 'containerd', 'category': 'Containerization', 'subcategory': 'Container Runtime',
     'common_names': json.dumps(['containerd']), 'cpe_vendor': 'linuxfoundation', 'cpe_product': 'containerd',
     'description': 'Industry-standard container runtime', 'website_url': 'https://containerd.io',
     'typical_versions': json.dumps(['1.6.x', '1.7.x']), 'is_popular': False},

    {'vendor': 'SUSE', 'product_name': 'Rancher', 'category': 'Orchestration', 'subcategory': 'Multi-Cluster Management',
     'common_names': json.dumps(['rancher']), 'cpe_vendor': 'suse', 'cpe_product': 'rancher',
     'description': 'Kubernetes management platform', 'website_url': 'https://rancher.com',
     'typical_versions': json.dumps(['2.6.x', '2.7.x', '2.8.x']), 'is_popular': True},

    # Configuration Management & Automation
    {'vendor': 'Red Hat', 'product_name': 'Ansible', 'category': 'Configuration Management', 'subcategory': 'Automation',
     'common_names': json.dumps(['ansible', 'ansible-core']), 'cpe_vendor': 'redhat', 'cpe_product': 'ansible',
     'description': 'IT automation platform', 'website_url': 'https://www.ansible.com',
     'typical_versions': json.dumps(['2.14.x', '2.15.x', '2.16.x']), 'is_popular': True},

    {'vendor': 'Puppet', 'product_name': 'Puppet', 'category': 'Configuration Management', 'subcategory': 'Infrastructure as Code',
     'common_names': json.dumps(['puppet', 'puppet-agent']), 'cpe_vendor': 'puppet', 'cpe_product': 'puppet',
     'description': 'Configuration management tool', 'website_url': 'https://puppet.com',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': False},

    {'vendor': 'Chef', 'product_name': 'Chef Infra', 'category': 'Configuration Management', 'subcategory': 'Infrastructure as Code',
     'common_names': json.dumps(['chef', 'chef-client']), 'cpe_vendor': 'chef', 'cpe_product': 'chef',
     'description': 'Infrastructure automation platform', 'website_url': 'https://www.chef.io',
     'typical_versions': json.dumps(['17.x', '18.x']), 'is_popular': False},

    {'vendor': 'SaltStack', 'product_name': 'Salt', 'category': 'Configuration Management', 'subcategory': 'Remote Execution',
     'common_names': json.dumps(['salt', 'saltstack']), 'cpe_vendor': 'saltstack', 'cpe_product': 'salt',
     'description': 'Event-driven IT automation', 'website_url': 'https://saltproject.io',
     'typical_versions': json.dumps(['3006.x']), 'is_popular': False},

    # High Availability & Load Balancing
    {'vendor': 'Keepalived', 'product_name': 'Keepalived', 'category': 'High Availability', 'subcategory': 'VRRP',
     'common_names': json.dumps(['keepalived']), 'cpe_vendor': 'keepalived', 'cpe_product': 'keepalived',
     'description': 'High availability and load balancing', 'website_url': 'https://www.keepalived.org',
     'typical_versions': json.dumps(['2.2.x', '2.3.x']), 'is_popular': True},

    {'vendor': 'HAProxy', 'product_name': 'HAProxy', 'category': 'Load Balancing', 'subcategory': 'Reverse Proxy',
     'common_names': json.dumps(['haproxy']), 'cpe_vendor': 'haproxy', 'cpe_product': 'haproxy',
     'description': 'High performance TCP/HTTP load balancer', 'website_url': 'https://www.haproxy.org',
     'typical_versions': json.dumps(['2.6.x', '2.7.x', '2.8.x', '2.9.x']), 'is_popular': True},

    {'vendor': 'ClusterLabs', 'product_name': 'Pacemaker', 'category': 'High Availability', 'subcategory': 'Cluster Resource Manager',
     'common_names': json.dumps(['pacemaker']), 'cpe_vendor': 'clusterlabs', 'cpe_product': 'pacemaker',
     'description': 'High availability cluster resource manager', 'website_url': 'https://clusterlabs.org',
     'typical_versions': json.dumps(['2.1.x']), 'is_popular': False},

    {'vendor': 'ClusterLabs', 'product_name': 'Corosync', 'category': 'High Availability', 'subcategory': 'Cluster Engine',
     'common_names': json.dumps(['corosync']), 'cpe_vendor': 'clusterlabs', 'cpe_product': 'corosync',
     'description': 'Group communication system', 'website_url': 'https://corosync.github.io/corosync',
     'typical_versions': json.dumps(['3.x']), 'is_popular': False},

    # CI/CD & DevOps
    {'vendor': 'Jenkins', 'product_name': 'Jenkins', 'category': 'CI/CD', 'subcategory': 'Continuous Integration',
     'common_names': json.dumps(['jenkins']), 'cpe_vendor': 'jenkins', 'cpe_product': 'jenkins',
     'description': 'Open source automation server', 'website_url': 'https://www.jenkins.io',
     'typical_versions': json.dumps(['2.400.x', '2.401.x', '2.426.x']), 'is_popular': True},

    {'vendor': 'GitLab', 'product_name': 'GitLab', 'category': 'CI/CD', 'subcategory': 'DevOps Platform',
     'common_names': json.dumps(['gitlab', 'gitlab-ce', 'gitlab-ee']), 'cpe_vendor': 'gitlab', 'cpe_product': 'gitlab',
     'description': 'Complete DevOps platform', 'website_url': 'https://gitlab.com',
     'typical_versions': json.dumps(['15.x', '16.x', '17.x']), 'is_popular': True},

    {'vendor': 'JetBrains', 'product_name': 'TeamCity', 'category': 'CI/CD', 'subcategory': 'Continuous Integration',
     'common_names': json.dumps(['teamcity']), 'cpe_vendor': 'jetbrains', 'cpe_product': 'teamcity',
     'description': 'Continuous integration and deployment server', 'website_url': 'https://www.jetbrains.com/teamcity',
     'typical_versions': json.dumps(['2023.x', '2024.x']), 'is_popular': False},

    # Patch Management & Deployment
    {'vendor': 'Microsoft', 'product_name': 'WSUS', 'category': 'Patch Management', 'subcategory': 'Windows Update',
     'common_names': json.dumps(['wsus', 'windows_server_update_services']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_server_update_services',
     'description': 'Windows Server Update Services', 'website_url': 'https://docs.microsoft.com/windows-server/administration/windows-server-update-services',
     'typical_versions': json.dumps(['Server 2016', 'Server 2019', 'Server 2022']), 'is_popular': True},

    {'vendor': 'PDQ', 'product_name': 'PDQ Deploy', 'category': 'Patch Management', 'subcategory': 'Software Deployment',
     'common_names': json.dumps(['pdq', 'pdq-deploy']), 'cpe_vendor': 'pdq', 'cpe_product': 'pdq_deploy',
     'description': 'Software deployment tool for Windows', 'website_url': 'https://www.pdq.com/pdq-deploy',
     'typical_versions': json.dumps(['19.x']), 'is_popular': True},

    {'vendor': 'Ivanti', 'product_name': 'Patch Manager', 'category': 'Patch Management', 'subcategory': 'Vulnerability Remediation',
     'common_names': json.dumps(['ivanti', 'patch-manager']), 'cpe_vendor': 'ivanti', 'cpe_product': 'patch_manager',
     'description': 'Enterprise patch management', 'website_url': 'https://www.ivanti.com',
     'typical_versions': json.dumps(['2023.x', '2024.x']), 'is_popular': False},

    {'vendor': 'ManageEngine', 'product_name': 'Patch Manager Plus', 'category': 'Patch Management', 'subcategory': 'Automated Patching',
     'common_names': json.dumps(['manageengine', 'patch-manager-plus']), 'cpe_vendor': 'zohocorp', 'cpe_product': 'manageengine_patch_manager_plus',
     'description': 'Automated patch deployment', 'website_url': 'https://www.manageengine.com/patch-management',
     'typical_versions': json.dumps(['11.x']), 'is_popular': False},

    # CRM & Business Applications
    {'vendor': 'SugarCRM', 'product_name': 'SugarCRM', 'category': 'CRM', 'subcategory': 'Customer Relationship Management',
     'common_names': json.dumps(['sugarcrm', 'sugar']), 'cpe_vendor': 'sugarcrm', 'cpe_product': 'sugarcrm',
     'description': 'Customer relationship management software', 'website_url': 'https://www.sugarcrm.com',
     'typical_versions': json.dumps(['12.x', '13.x', '14.x']), 'is_popular': True},

    {'vendor': 'Salesforce', 'product_name': 'Salesforce', 'category': 'CRM', 'subcategory': 'Cloud CRM',
     'common_names': json.dumps(['salesforce', 'sfdc']), 'cpe_vendor': 'salesforce', 'cpe_product': 'salesforce',
     'description': 'Cloud-based CRM platform', 'website_url': 'https://www.salesforce.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Dynamics 365', 'category': 'CRM', 'subcategory': 'Enterprise CRM',
     'common_names': json.dumps(['dynamics', 'dynamics-365', 'd365']), 'cpe_vendor': 'microsoft', 'cpe_product': 'dynamics_365',
     'description': 'Business applications suite', 'website_url': 'https://dynamics.microsoft.com',
     'typical_versions': json.dumps(['Cloud', 'On-Premise']), 'is_popular': True},

    # Issue Tracking & Project Management
    {'vendor': 'Atlassian', 'product_name': 'Jira', 'category': 'Issue Tracking', 'subcategory': 'Project Management',
     'common_names': json.dumps(['jira', 'jira-software']), 'cpe_vendor': 'atlassian', 'cpe_product': 'jira',
     'description': 'Issue and project tracking software', 'website_url': 'https://www.atlassian.com/software/jira',
     'typical_versions': json.dumps(['9.x', '10.x']), 'is_popular': True},

    {'vendor': 'JetBrains', 'product_name': 'YouTrack', 'category': 'Issue Tracking', 'subcategory': 'Issue Management',
     'common_names': json.dumps(['youtrack']), 'cpe_vendor': 'jetbrains', 'cpe_product': 'youtrack',
     'description': 'Issue tracking and project management', 'website_url': 'https://www.jetbrains.com/youtrack',
     'typical_versions': json.dumps(['2023.x', '2024.x']), 'is_popular': True},

    {'vendor': 'Redmine', 'product_name': 'Redmine', 'category': 'Issue Tracking', 'subcategory': 'Project Management',
     'common_names': json.dumps(['redmine']), 'cpe_vendor': 'redmine', 'cpe_product': 'redmine',
     'description': 'Flexible project management web application', 'website_url': 'https://www.redmine.org',
     'typical_versions': json.dumps(['5.x']), 'is_popular': False},

    {'vendor': 'Atlassian', 'product_name': 'Confluence', 'category': 'Collaboration', 'subcategory': 'Team Wiki',
     'common_names': json.dumps(['confluence']), 'cpe_vendor': 'atlassian', 'cpe_product': 'confluence',
     'description': 'Team collaboration and knowledge base', 'website_url': 'https://www.atlassian.com/software/confluence',
     'typical_versions': json.dumps(['8.x']), 'is_popular': True},

    # Web Servers
    {'vendor': 'Apache', 'product_name': 'Apache HTTP Server', 'category': 'Web Server', 'subcategory': 'HTTP Server',
     'common_names': json.dumps(['apache', 'httpd', 'apache2']), 'cpe_vendor': 'apache', 'cpe_product': 'http_server',
     'description': 'Open source HTTP server', 'website_url': 'https://httpd.apache.org',
     'typical_versions': json.dumps(['2.4.x']), 'is_popular': True},

    {'vendor': 'Nginx', 'product_name': 'Nginx', 'category': 'Web Server', 'subcategory': 'HTTP Server',
     'common_names': json.dumps(['nginx']), 'cpe_vendor': 'nginx', 'cpe_product': 'nginx',
     'description': 'High-performance web server and reverse proxy', 'website_url': 'https://nginx.org',
     'typical_versions': json.dumps(['1.24.x', '1.25.x', '1.26.x']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'IIS', 'category': 'Web Server', 'subcategory': 'Windows Web Server',
     'common_names': json.dumps(['iis', 'internet_information_services']), 'cpe_vendor': 'microsoft', 'cpe_product': 'internet_information_services',
     'description': 'Internet Information Services', 'website_url': 'https://www.iis.net',
     'typical_versions': json.dumps(['10.0']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'Tomcat', 'category': 'Application Server', 'subcategory': 'Java Servlet Container',
     'common_names': json.dumps(['tomcat', 'apache-tomcat']), 'cpe_vendor': 'apache', 'cpe_product': 'tomcat',
     'description': 'Java Servlet and JSP container', 'website_url': 'https://tomcat.apache.org',
     'typical_versions': json.dumps(['9.x', '10.x', '11.x']), 'is_popular': True},

    {'vendor': 'Lighttpd', 'product_name': 'Lighttpd', 'category': 'Web Server', 'subcategory': 'Lightweight HTTP Server',
     'common_names': json.dumps(['lighttpd', 'lighty']), 'cpe_vendor': 'lighttpd', 'cpe_product': 'lighttpd',
     'description': 'Secure, fast, and flexible web server', 'website_url': 'https://www.lighttpd.net',
     'typical_versions': json.dumps(['1.4.x']), 'is_popular': False},

    # Databases
    {'vendor': 'MySQL', 'product_name': 'MySQL', 'category': 'Database', 'subcategory': 'Relational Database',
     'common_names': json.dumps(['mysql', 'mysql-server']), 'cpe_vendor': 'oracle', 'cpe_product': 'mysql',
     'description': 'Open source relational database', 'website_url': 'https://www.mysql.com',
     'typical_versions': json.dumps(['5.7.x', '8.0.x', '8.1.x']), 'is_popular': True},

    {'vendor': 'PostgreSQL', 'product_name': 'PostgreSQL', 'category': 'Database', 'subcategory': 'Relational Database',
     'common_names': json.dumps(['postgresql', 'postgres', 'pgsql']), 'cpe_vendor': 'postgresql', 'cpe_product': 'postgresql',
     'description': 'Advanced open source relational database', 'website_url': 'https://www.postgresql.org',
     'typical_versions': json.dumps(['14.x', '15.x', '16.x']), 'is_popular': True},

    {'vendor': 'MongoDB', 'product_name': 'MongoDB', 'category': 'Database', 'subcategory': 'NoSQL Database',
     'common_names': json.dumps(['mongodb', 'mongo']), 'cpe_vendor': 'mongodb', 'cpe_product': 'mongodb',
     'description': 'Document-oriented NoSQL database', 'website_url': 'https://www.mongodb.com',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Redis', 'product_name': 'Redis', 'category': 'Database', 'subcategory': 'In-Memory Data Store',
     'common_names': json.dumps(['redis', 'redis-server']), 'cpe_vendor': 'redis', 'cpe_product': 'redis',
     'description': 'In-memory data structure store', 'website_url': 'https://redis.io',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'SQL Server', 'category': 'Database', 'subcategory': 'Relational Database',
     'common_names': json.dumps(['sql-server', 'mssql', 'sqlserver']), 'cpe_vendor': 'microsoft', 'cpe_product': 'sql_server',
     'description': 'Enterprise relational database', 'website_url': 'https://www.microsoft.com/sql-server',
     'typical_versions': json.dumps(['2016', '2017', '2019', '2022']), 'is_popular': True},

    {'vendor': 'MariaDB', 'product_name': 'MariaDB', 'category': 'Database', 'subcategory': 'Relational Database',
     'common_names': json.dumps(['mariadb', 'mariadb-server']), 'cpe_vendor': 'mariadb', 'cpe_product': 'mariadb',
     'description': 'MySQL-compatible database server', 'website_url': 'https://mariadb.org',
     'typical_versions': json.dumps(['10.6.x', '10.11.x', '11.x']), 'is_popular': True},

    {'vendor': 'Elastic', 'product_name': 'Elasticsearch', 'category': 'Database', 'subcategory': 'Search Engine',
     'common_names': json.dumps(['elasticsearch', 'elastic']), 'cpe_vendor': 'elastic', 'cpe_product': 'elasticsearch',
     'description': 'Distributed search and analytics engine', 'website_url': 'https://www.elastic.co/elasticsearch',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    # Virtualization
    {'vendor': 'VMware', 'product_name': 'vSphere', 'category': 'Virtualization', 'subcategory': 'Hypervisor',
     'common_names': json.dumps(['vsphere', 'vcenter', 'esxi']), 'cpe_vendor': 'vmware', 'cpe_product': 'vsphere',
     'description': 'Enterprise virtualization platform', 'website_url': 'https://www.vmware.com/products/vsphere.html',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Hyper-V', 'category': 'Virtualization', 'subcategory': 'Windows Hypervisor',
     'common_names': json.dumps(['hyper-v', 'hyperv']), 'cpe_vendor': 'microsoft', 'cpe_product': 'hyper-v',
     'description': 'Windows Server virtualization', 'website_url': 'https://docs.microsoft.com/virtualization/hyper-v-on-windows',
     'typical_versions': json.dumps(['Server 2016', 'Server 2019', 'Server 2022']), 'is_popular': True},

    {'vendor': 'Red Hat', 'product_name': 'KVM', 'category': 'Virtualization', 'subcategory': 'Linux Hypervisor',
     'common_names': json.dumps(['kvm', 'qemu-kvm']), 'cpe_vendor': 'redhat', 'cpe_product': 'kernel-based_virtual_machine',
     'description': 'Kernel-based Virtual Machine', 'website_url': 'https://www.linux-kvm.org',
     'typical_versions': json.dumps(['Various']), 'is_popular': True},

    {'vendor': 'Proxmox', 'product_name': 'Proxmox VE', 'category': 'Virtualization', 'subcategory': 'Open Source Virtualization',
     'common_names': json.dumps(['proxmox', 'pve']), 'cpe_vendor': 'proxmox', 'cpe_product': 'virtual_environment',
     'description': 'Open-source server virtualization platform', 'website_url': 'https://www.proxmox.com',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    {'vendor': 'Citrix', 'product_name': 'XenServer', 'category': 'Virtualization', 'subcategory': 'Hypervisor',
     'common_names': json.dumps(['xenserver', 'xen']), 'cpe_vendor': 'citrix', 'cpe_product': 'xenserver',
     'description': 'Enterprise server virtualization', 'website_url': 'https://www.citrix.com/products/citrix-hypervisor',
     'typical_versions': json.dumps(['8.x']), 'is_popular': False},

    # Operating Systems - Windows
    {'vendor': 'Microsoft', 'product_name': 'Windows Server 2016', 'category': 'Operating System', 'subcategory': 'Windows Server',
     'common_names': json.dumps(['windows-server', 'windows-server-2016']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_server_2016',
     'description': 'Windows Server operating system', 'website_url': 'https://www.microsoft.com/windows-server',
     'typical_versions': json.dumps(['1607']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Windows Server 2019', 'category': 'Operating System', 'subcategory': 'Windows Server',
     'common_names': json.dumps(['windows-server', 'windows-server-2019']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_server_2019',
     'description': 'Windows Server operating system', 'website_url': 'https://www.microsoft.com/windows-server',
     'typical_versions': json.dumps(['1809']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Windows Server 2022', 'category': 'Operating System', 'subcategory': 'Windows Server',
     'common_names': json.dumps(['windows-server', 'windows-server-2022']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_server_2022',
     'description': 'Windows Server operating system', 'website_url': 'https://www.microsoft.com/windows-server',
     'typical_versions': json.dumps(['21H2']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Windows 10', 'category': 'Operating System', 'subcategory': 'Windows Desktop',
     'common_names': json.dumps(['windows', 'windows-10', 'win10']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_10',
     'description': 'Windows desktop operating system', 'website_url': 'https://www.microsoft.com/windows',
     'typical_versions': json.dumps(['20H2', '21H1', '21H2', '22H2']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Windows 11', 'category': 'Operating System', 'subcategory': 'Windows Desktop',
     'common_names': json.dumps(['windows', 'windows-11', 'win11']), 'cpe_vendor': 'microsoft', 'cpe_product': 'windows_11',
     'description': 'Windows desktop operating system', 'website_url': 'https://www.microsoft.com/windows',
     'typical_versions': json.dumps(['21H2', '22H2', '23H2']), 'is_popular': True},

    # Operating Systems - Linux
    {'vendor': 'Red Hat', 'product_name': 'Red Hat Enterprise Linux', 'category': 'Operating System', 'subcategory': 'Linux Server',
     'common_names': json.dumps(['rhel', 'red-hat', 'redhat-linux']), 'cpe_vendor': 'redhat', 'cpe_product': 'enterprise_linux',
     'description': 'Enterprise Linux distribution', 'website_url': 'https://www.redhat.com/rhel',
     'typical_versions': json.dumps(['7.x', '8.x', '9.x']), 'is_popular': True},

    {'vendor': 'Ubuntu', 'product_name': 'Ubuntu', 'category': 'Operating System', 'subcategory': 'Linux Desktop/Server',
     'common_names': json.dumps(['ubuntu', 'ubuntu-linux']), 'cpe_vendor': 'canonical', 'cpe_product': 'ubuntu_linux',
     'description': 'Debian-based Linux distribution', 'website_url': 'https://ubuntu.com',
     'typical_versions': json.dumps(['20.04', '22.04', '24.04']), 'is_popular': True},

    {'vendor': 'Debian', 'product_name': 'Debian', 'category': 'Operating System', 'subcategory': 'Linux Server',
     'common_names': json.dumps(['debian', 'debian-linux']), 'cpe_vendor': 'debian', 'cpe_product': 'debian_linux',
     'description': 'Universal operating system', 'website_url': 'https://www.debian.org',
     'typical_versions': json.dumps(['10', '11', '12']), 'is_popular': True},

    {'vendor': 'SUSE', 'product_name': 'SUSE Linux Enterprise Server', 'category': 'Operating System', 'subcategory': 'Linux Server',
     'common_names': json.dumps(['sles', 'suse', 'suse-linux']), 'cpe_vendor': 'suse', 'cpe_product': 'linux_enterprise_server',
     'description': 'Enterprise Linux server', 'website_url': 'https://www.suse.com/products/server',
     'typical_versions': json.dumps(['12', '15']), 'is_popular': True},

    {'vendor': 'CentOS', 'product_name': 'CentOS', 'category': 'Operating System', 'subcategory': 'Linux Server',
     'common_names': json.dumps(['centos', 'centos-linux']), 'cpe_vendor': 'centos', 'cpe_product': 'centos',
     'description': 'Community Enterprise Operating System', 'website_url': 'https://www.centos.org',
     'typical_versions': json.dumps(['7', '8', 'Stream 8', 'Stream 9']), 'is_popular': True},

    # Backup & Recovery
    {'vendor': 'Veeam', 'product_name': 'Backup & Replication', 'category': 'Backup', 'subcategory': 'Data Protection',
     'common_names': json.dumps(['veeam', 'veeam-backup']), 'cpe_vendor': 'veeam', 'cpe_product': 'backup_and_replication',
     'description': 'Backup, recovery and replication software', 'website_url': 'https://www.veeam.com',
     'typical_versions': json.dumps(['11.x', '12.x']), 'is_popular': True},

    {'vendor': 'Bacula', 'product_name': 'Bacula', 'category': 'Backup', 'subcategory': 'Open Source Backup',
     'common_names': json.dumps(['bacula']), 'cpe_vendor': 'bacula', 'cpe_product': 'bacula',
     'description': 'Open source network backup solution', 'website_url': 'https://www.bacula.org',
     'typical_versions': json.dumps(['11.x', '13.x']), 'is_popular': False},

    {'vendor': 'Acronis', 'product_name': 'Cyber Protect', 'category': 'Backup', 'subcategory': 'Cyber Protection',
     'common_names': json.dumps(['acronis', 'acronis-backup']), 'cpe_vendor': 'acronis', 'cpe_product': 'cyber_protect',
     'description': 'Integrated backup and cybersecurity', 'website_url': 'https://www.acronis.com',
     'typical_versions': json.dumps(['15', '16']), 'is_popular': False},

    # Monitoring & Observability
    {'vendor': 'Nagios', 'product_name': 'Nagios', 'category': 'Monitoring', 'subcategory': 'Infrastructure Monitoring',
     'common_names': json.dumps(['nagios', 'nagios-core']), 'cpe_vendor': 'nagios', 'cpe_product': 'nagios',
     'description': 'IT infrastructure monitoring', 'website_url': 'https://www.nagios.org',
     'typical_versions': json.dumps(['4.x']), 'is_popular': True},

    {'vendor': 'Zabbix', 'product_name': 'Zabbix', 'category': 'Monitoring', 'subcategory': 'Enterprise Monitoring',
     'common_names': json.dumps(['zabbix']), 'cpe_vendor': 'zabbix', 'cpe_product': 'zabbix',
     'description': 'Enterprise-class monitoring solution', 'website_url': 'https://www.zabbix.com',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Prometheus', 'product_name': 'Prometheus', 'category': 'Monitoring', 'subcategory': 'Metrics Monitoring',
     'common_names': json.dumps(['prometheus']), 'cpe_vendor': 'prometheus', 'cpe_product': 'prometheus',
     'description': 'Systems monitoring and alerting toolkit', 'website_url': 'https://prometheus.io',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Grafana', 'product_name': 'Grafana', 'category': 'Monitoring', 'subcategory': 'Visualization',
     'common_names': json.dumps(['grafana']), 'cpe_vendor': 'grafana', 'cpe_product': 'grafana',
     'description': 'Metrics dashboard and graph editor', 'website_url': 'https://grafana.com',
     'typical_versions': json.dumps(['9.x', '10.x']), 'is_popular': True},

    # VPN & Remote Access
    {'vendor': 'OpenVPN', 'product_name': 'OpenVPN', 'category': 'VPN', 'subcategory': 'Virtual Private Network',
     'common_names': json.dumps(['openvpn']), 'cpe_vendor': 'openvpn', 'cpe_product': 'openvpn',
     'description': 'Open source VPN', 'website_url': 'https://openvpn.net',
     'typical_versions': json.dumps(['2.5.x', '2.6.x']), 'is_popular': True},

    {'vendor': 'WireGuard', 'product_name': 'WireGuard', 'category': 'VPN', 'subcategory': 'Modern VPN',
     'common_names': json.dumps(['wireguard']), 'cpe_vendor': 'wireguard', 'cpe_product': 'wireguard',
     'description': 'Fast and modern VPN', 'website_url': 'https://www.wireguard.com',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    {'vendor': 'Fortinet', 'product_name': 'FortiClient', 'category': 'VPN', 'subcategory': 'Enterprise VPN Client',
     'common_names': json.dumps(['forticlient', 'fortinet']), 'cpe_vendor': 'fortinet', 'cpe_product': 'forticlient',
     'description': 'Endpoint security suite with VPN', 'website_url': 'https://www.fortinet.com/products/endpoint-security/forticlient',
     'typical_versions': json.dumps(['7.x']), 'is_popular': True},

    # DNS & Network Services
    {'vendor': 'ISC', 'product_name': 'BIND', 'category': 'DNS', 'subcategory': 'Name Server',
     'common_names': json.dumps(['bind', 'bind9', 'named']), 'cpe_vendor': 'isc', 'cpe_product': 'bind',
     'description': 'Berkeley Internet Name Domain', 'website_url': 'https://www.isc.org/bind',
     'typical_versions': json.dumps(['9.16.x', '9.18.x']), 'is_popular': True},

    {'vendor': 'PowerDNS', 'product_name': 'PowerDNS', 'category': 'DNS', 'subcategory': 'Authoritative DNS',
     'common_names': json.dumps(['powerdns', 'pdns']), 'cpe_vendor': 'powerdns', 'cpe_product': 'authoritative_server',
     'description': 'High-performance DNS server', 'website_url': 'https://www.powerdns.com',
     'typical_versions': json.dumps(['4.x']), 'is_popular': False},

    {'vendor': 'Unbound', 'product_name': 'Unbound', 'category': 'DNS', 'subcategory': 'Recursive DNS',
     'common_names': json.dumps(['unbound']), 'cpe_vendor': 'nlnetlabs', 'cpe_product': 'unbound',
     'description': 'Validating, recursive DNS resolver', 'website_url': 'https://www.nlnetlabs.nl/projects/unbound',
     'typical_versions': json.dumps(['1.x']), 'is_popular': False},

    # Mail Servers
    {'vendor': 'Postfix', 'product_name': 'Postfix', 'category': 'Mail Server', 'subcategory': 'SMTP Server',
     'common_names': json.dumps(['postfix']), 'cpe_vendor': 'postfix', 'cpe_product': 'postfix',
     'description': 'Mail transfer agent', 'website_url': 'http://www.postfix.org',
     'typical_versions': json.dumps(['3.x']), 'is_popular': True},

    {'vendor': 'Dovecot', 'product_name': 'Dovecot', 'category': 'Mail Server', 'subcategory': 'IMAP/POP3 Server',
     'common_names': json.dumps(['dovecot']), 'cpe_vendor': 'dovecot', 'cpe_product': 'dovecot',
     'description': 'Open source IMAP and POP3 server', 'website_url': 'https://www.dovecot.org',
     'typical_versions': json.dumps(['2.3.x']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Exchange Server', 'category': 'Mail Server', 'subcategory': 'Enterprise Mail',
     'common_names': json.dumps(['exchange', 'exchange-server']), 'cpe_vendor': 'microsoft', 'cpe_product': 'exchange_server',
     'description': 'Enterprise mail and calendaring server', 'website_url': 'https://www.microsoft.com/exchange',
     'typical_versions': json.dumps(['2016', '2019', '2022']), 'is_popular': True},

    # Programming Languages & Runtimes
    {'vendor': 'PHP', 'product_name': 'PHP', 'category': 'Programming Language', 'subcategory': 'Server-Side Scripting',
     'common_names': json.dumps(['php', 'php-fpm']), 'cpe_vendor': 'php', 'cpe_product': 'php',
     'description': 'Server-side scripting language', 'website_url': 'https://www.php.net',
     'typical_versions': json.dumps(['7.4.x', '8.0.x', '8.1.x', '8.2.x', '8.3.x']), 'is_popular': True},

    {'vendor': 'Python', 'product_name': 'Python', 'category': 'Programming Language', 'subcategory': 'Interpreted Language',
     'common_names': json.dumps(['python', 'python3']), 'cpe_vendor': 'python', 'cpe_product': 'python',
     'description': 'High-level programming language', 'website_url': 'https://www.python.org',
     'typical_versions': json.dumps(['3.9.x', '3.10.x', '3.11.x', '3.12.x']), 'is_popular': True},

    {'vendor': 'Node.js', 'product_name': 'Node.js', 'category': 'Programming Language', 'subcategory': 'JavaScript Runtime',
     'common_names': json.dumps(['nodejs', 'node']), 'cpe_vendor': 'nodejs', 'cpe_product': 'node.js',
     'description': 'JavaScript runtime built on Chrome V8', 'website_url': 'https://nodejs.org',
     'typical_versions': json.dumps(['18.x', '20.x', '21.x']), 'is_popular': True},

    {'vendor': 'Oracle', 'product_name': 'Java', 'category': 'Programming Language', 'subcategory': 'Runtime Environment',
     'common_names': json.dumps(['java', 'jre', 'jdk', 'openjdk']), 'cpe_vendor': 'oracle', 'cpe_product': 'jre',
     'description': 'Java Runtime Environment', 'website_url': 'https://www.oracle.com/java',
     'typical_versions': json.dumps(['8', '11', '17', '21']), 'is_popular': True},

    # Content Management Systems
    {'vendor': 'WordPress', 'product_name': 'WordPress', 'category': 'CMS', 'subcategory': 'Content Management',
     'common_names': json.dumps(['wordpress', 'wp']), 'cpe_vendor': 'wordpress', 'cpe_product': 'wordpress',
     'description': 'Open source CMS', 'website_url': 'https://wordpress.org',
     'typical_versions': json.dumps(['6.x']), 'is_popular': True},

    {'vendor': 'Drupal', 'product_name': 'Drupal', 'category': 'CMS', 'subcategory': 'Content Management',
     'common_names': json.dumps(['drupal']), 'cpe_vendor': 'drupal', 'cpe_product': 'drupal',
     'description': 'Open source CMS platform', 'website_url': 'https://www.drupal.org',
     'typical_versions': json.dumps(['9.x', '10.x']), 'is_popular': True},

    {'vendor': 'Joomla', 'product_name': 'Joomla', 'category': 'CMS', 'subcategory': 'Content Management',
     'common_names': json.dumps(['joomla']), 'cpe_vendor': 'joomla', 'cpe_product': 'joomla',
     'description': 'Open source CMS', 'website_url': 'https://www.joomla.org',
     'typical_versions': json.dumps(['4.x', '5.x']), 'is_popular': False},

    # Security & Firewall
    {'vendor': 'pfSense', 'product_name': 'pfSense', 'category': 'Firewall', 'subcategory': 'Network Security',
     'common_names': json.dumps(['pfsense']), 'cpe_vendor': 'netgate', 'cpe_product': 'pfsense',
     'description': 'Open source firewall and router', 'website_url': 'https://www.pfsense.org',
     'typical_versions': json.dumps(['2.6.x', '2.7.x']), 'is_popular': True},

    {'vendor': 'IPTables', 'product_name': 'IPTables', 'category': 'Firewall', 'subcategory': 'Linux Firewall',
     'common_names': json.dumps(['iptables', 'netfilter']), 'cpe_vendor': 'netfilter', 'cpe_product': 'iptables',
     'description': 'Linux kernel firewall', 'website_url': 'https://www.netfilter.org',
     'typical_versions': json.dumps(['1.8.x']), 'is_popular': True},

    {'vendor': 'Snort', 'product_name': 'Snort', 'category': 'Security', 'subcategory': 'IDS/IPS',
     'common_names': json.dumps(['snort']), 'cpe_vendor': 'snort', 'cpe_product': 'snort',
     'description': 'Network intrusion detection system', 'website_url': 'https://www.snort.org',
     'typical_versions': json.dumps(['2.9.x', '3.x']), 'is_popular': True},

    # File Sharing & Storage
    {'vendor': 'Samba', 'product_name': 'Samba', 'category': 'File Sharing', 'subcategory': 'SMB/CIFS Server',
     'common_names': json.dumps(['samba', 'smbd']), 'cpe_vendor': 'samba', 'cpe_product': 'samba',
     'description': 'Windows interoperability suite', 'website_url': 'https://www.samba.org',
     'typical_versions': json.dumps(['4.x']), 'is_popular': True},

    {'vendor': 'Nextcloud', 'product_name': 'Nextcloud', 'category': 'File Sharing', 'subcategory': 'Cloud Storage',
     'common_names': json.dumps(['nextcloud']), 'cpe_vendor': 'nextcloud', 'cpe_product': 'nextcloud_server',
     'description': 'Self-hosted productivity platform', 'website_url': 'https://nextcloud.com',
     'typical_versions': json.dumps(['26.x', '27.x', '28.x']), 'is_popular': True},

    {'vendor': 'ownCloud', 'product_name': 'ownCloud', 'category': 'File Sharing', 'subcategory': 'Cloud Storage',
     'common_names': json.dumps(['owncloud']), 'cpe_vendor': 'owncloud', 'cpe_product': 'owncloud',
     'description': 'File sync and share solution', 'website_url': 'https://owncloud.com',
     'typical_versions': json.dumps(['10.x']), 'is_popular': False},

    # Version Control
    {'vendor': 'Git', 'product_name': 'Git', 'category': 'Version Control', 'subcategory': 'Distributed VCS',
     'common_names': json.dumps(['git']), 'cpe_vendor': 'git-scm', 'cpe_product': 'git',
     'description': 'Distributed version control system', 'website_url': 'https://git-scm.com',
     'typical_versions': json.dumps(['2.40.x', '2.41.x', '2.42.x', '2.43.x']), 'is_popular': True},

    {'vendor': 'Atlassian', 'product_name': 'Bitbucket', 'category': 'Version Control', 'subcategory': 'Git Repository Management',
     'common_names': json.dumps(['bitbucket']), 'cpe_vendor': 'atlassian', 'cpe_product': 'bitbucket',
     'description': 'Git repository management', 'website_url': 'https://bitbucket.org',
     'typical_versions': json.dumps(['8.x']), 'is_popular': True},

    # SSH & Remote Access
    {'vendor': 'OpenSSH', 'product_name': 'OpenSSH', 'category': 'Remote Access', 'subcategory': 'SSH Server',
     'common_names': json.dumps(['openssh', 'sshd', 'ssh']), 'cpe_vendor': 'openbsd', 'cpe_product': 'openssh',
     'description': 'OpenBSD Secure Shell', 'website_url': 'https://www.openssh.com',
     'typical_versions': json.dumps(['8.x', '9.x']), 'is_popular': True},

    # Message Queues
    {'vendor': 'RabbitMQ', 'product_name': 'RabbitMQ', 'category': 'Message Queue', 'subcategory': 'AMQP Broker',
     'common_names': json.dumps(['rabbitmq']), 'cpe_vendor': 'vmware', 'cpe_product': 'rabbitmq',
     'description': 'Message broker software', 'website_url': 'https://www.rabbitmq.com',
     'typical_versions': json.dumps(['3.11.x', '3.12.x']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'Kafka', 'category': 'Message Queue', 'subcategory': 'Streaming Platform',
     'common_names': json.dumps(['kafka', 'apache-kafka']), 'cpe_vendor': 'apache', 'cpe_product': 'kafka',
     'description': 'Distributed event streaming platform', 'website_url': 'https://kafka.apache.org',
     'typical_versions': json.dumps(['3.x']), 'is_popular': True},

    # Cache
    {'vendor': 'Memcached', 'product_name': 'Memcached', 'category': 'Cache', 'subcategory': 'Memory Object Cache',
     'common_names': json.dumps(['memcached']), 'cpe_vendor': 'memcached', 'cpe_product': 'memcached',
     'description': 'Distributed memory object caching system', 'website_url': 'https://memcached.org',
     'typical_versions': json.dumps(['1.6.x']), 'is_popular': True},

    {'vendor': 'Varnish', 'product_name': 'Varnish Cache', 'category': 'Cache', 'subcategory': 'HTTP Accelerator',
     'common_names': json.dumps(['varnish', 'varnish-cache']), 'cpe_vendor': 'varnish-cache', 'cpe_product': 'varnish_cache',
     'description': 'Web application accelerator', 'website_url': 'https://varnish-cache.org',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    # ==================== NETWORK EQUIPMENT ====================
    {'vendor': 'Cisco', 'product_name': 'IOS', 'category': 'Network', 'subcategory': 'Router/Switch OS',
     'common_names': json.dumps(['cisco-ios', 'ios']), 'cpe_vendor': 'cisco', 'cpe_product': 'ios',
     'description': 'Cisco Internetwork Operating System', 'website_url': 'https://www.cisco.com',
     'typical_versions': json.dumps(['15.x', '17.x']), 'is_popular': True},

    {'vendor': 'Cisco', 'product_name': 'IOS XE', 'category': 'Network', 'subcategory': 'Router/Switch OS',
     'common_names': json.dumps(['ios-xe', 'cisco-ios-xe']), 'cpe_vendor': 'cisco', 'cpe_product': 'ios_xe',
     'description': 'Cisco IOS XE Software', 'website_url': 'https://www.cisco.com',
     'typical_versions': json.dumps(['16.x', '17.x']), 'is_popular': True},

    {'vendor': 'Cisco', 'product_name': 'NX-OS', 'category': 'Network', 'subcategory': 'Data Center Switch OS',
     'common_names': json.dumps(['nx-os', 'nxos']), 'cpe_vendor': 'cisco', 'cpe_product': 'nx-os',
     'description': 'Cisco Nexus Operating System', 'website_url': 'https://www.cisco.com',
     'typical_versions': json.dumps(['9.x', '10.x']), 'is_popular': True},

    {'vendor': 'Cisco', 'product_name': 'ASA', 'category': 'Firewall', 'subcategory': 'Enterprise Firewall',
     'common_names': json.dumps(['asa', 'cisco-asa']), 'cpe_vendor': 'cisco', 'cpe_product': 'adaptive_security_appliance_software',
     'description': 'Cisco Adaptive Security Appliance', 'website_url': 'https://www.cisco.com',
     'typical_versions': json.dumps(['9.x']), 'is_popular': True},

    {'vendor': 'Cisco', 'product_name': 'Firepower', 'category': 'Firewall', 'subcategory': 'NGFW',
     'common_names': json.dumps(['firepower', 'fmc', 'ftd']), 'cpe_vendor': 'cisco', 'cpe_product': 'firepower_threat_defense',
     'description': 'Cisco Firepower Threat Defense', 'website_url': 'https://www.cisco.com',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Palo Alto Networks', 'product_name': 'PAN-OS', 'category': 'Firewall', 'subcategory': 'NGFW',
     'common_names': json.dumps(['pan-os', 'panos', 'paloalto']), 'cpe_vendor': 'paloaltonetworks', 'cpe_product': 'pan-os',
     'description': 'Palo Alto Networks Operating System', 'website_url': 'https://www.paloaltonetworks.com',
     'typical_versions': json.dumps(['10.x', '11.x']), 'is_popular': True},

    {'vendor': 'Fortinet', 'product_name': 'FortiOS', 'category': 'Firewall', 'subcategory': 'NGFW',
     'common_names': json.dumps(['fortios', 'fortigate']), 'cpe_vendor': 'fortinet', 'cpe_product': 'fortios',
     'description': 'Fortinet FortiGate Operating System', 'website_url': 'https://www.fortinet.com',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Juniper', 'product_name': 'Junos OS', 'category': 'Network', 'subcategory': 'Router/Switch OS',
     'common_names': json.dumps(['junos', 'juniper']), 'cpe_vendor': 'juniper', 'cpe_product': 'junos',
     'description': 'Juniper Networks Operating System', 'website_url': 'https://www.juniper.net',
     'typical_versions': json.dumps(['21.x', '22.x', '23.x']), 'is_popular': True},

    {'vendor': 'Arista', 'product_name': 'EOS', 'category': 'Network', 'subcategory': 'Data Center Switch OS',
     'common_names': json.dumps(['arista-eos', 'eos']), 'cpe_vendor': 'arista', 'cpe_product': 'eos',
     'description': 'Arista Extensible Operating System', 'website_url': 'https://www.arista.com',
     'typical_versions': json.dumps(['4.x']), 'is_popular': True},

    {'vendor': 'F5', 'product_name': 'BIG-IP', 'category': 'Load Balancing', 'subcategory': 'ADC',
     'common_names': json.dumps(['big-ip', 'f5', 'bigip']), 'cpe_vendor': 'f5', 'cpe_product': 'big-ip_access_policy_manager',
     'description': 'F5 BIG-IP Application Delivery Controller', 'website_url': 'https://www.f5.com',
     'typical_versions': json.dumps(['15.x', '16.x', '17.x']), 'is_popular': True},

    {'vendor': 'Ubiquiti', 'product_name': 'UniFi', 'category': 'Network', 'subcategory': 'Wireless Network',
     'common_names': json.dumps(['unifi', 'ubiquiti']), 'cpe_vendor': 'ui', 'cpe_product': 'unifi_network_application',
     'description': 'Ubiquiti UniFi Network Management', 'website_url': 'https://ui.com',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    # ==================== SECURITY PRODUCTS ====================
    {'vendor': 'CrowdStrike', 'product_name': 'Falcon', 'category': 'Security', 'subcategory': 'EDR',
     'common_names': json.dumps(['crowdstrike', 'falcon']), 'cpe_vendor': 'crowdstrike', 'cpe_product': 'falcon',
     'description': 'Endpoint Detection and Response', 'website_url': 'https://www.crowdstrike.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Carbon Black', 'product_name': 'Carbon Black', 'category': 'Security', 'subcategory': 'EDR',
     'common_names': json.dumps(['carbon-black', 'cb']), 'cpe_vendor': 'vmware', 'cpe_product': 'carbon_black_cloud',
     'description': 'Endpoint Security Platform', 'website_url': 'https://www.carbonblack.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'SentinelOne', 'product_name': 'Singularity', 'category': 'Security', 'subcategory': 'EDR',
     'common_names': json.dumps(['sentinelone', 's1']), 'cpe_vendor': 'sentinelone', 'cpe_product': 'singularity',
     'description': 'AI-powered Endpoint Protection', 'website_url': 'https://www.sentinelone.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Symantec', 'product_name': 'Endpoint Protection', 'category': 'Security', 'subcategory': 'Antivirus',
     'common_names': json.dumps(['symantec', 'sep']), 'cpe_vendor': 'broadcom', 'cpe_product': 'symantec_endpoint_protection',
     'description': 'Enterprise Endpoint Protection', 'website_url': 'https://www.broadcom.com',
     'typical_versions': json.dumps(['14.x']), 'is_popular': True},

    {'vendor': 'McAfee', 'product_name': 'Endpoint Security', 'category': 'Security', 'subcategory': 'Antivirus',
     'common_names': json.dumps(['mcafee', 'ens']), 'cpe_vendor': 'mcafee', 'cpe_product': 'endpoint_security',
     'description': 'McAfee Endpoint Security', 'website_url': 'https://www.mcafee.com',
     'typical_versions': json.dumps(['10.x']), 'is_popular': True},

    {'vendor': 'Trend Micro', 'product_name': 'Apex One', 'category': 'Security', 'subcategory': 'Antivirus',
     'common_names': json.dumps(['trend-micro', 'apex-one']), 'cpe_vendor': 'trendmicro', 'cpe_product': 'apex_one',
     'description': 'Endpoint Security Solution', 'website_url': 'https://www.trendmicro.com',
     'typical_versions': json.dumps(['2019', 'SaaS']), 'is_popular': True},

    {'vendor': 'Splunk', 'product_name': 'Splunk Enterprise', 'category': 'SIEM', 'subcategory': 'Log Management',
     'common_names': json.dumps(['splunk']), 'cpe_vendor': 'splunk', 'cpe_product': 'splunk',
     'description': 'Data Platform for Security and Observability', 'website_url': 'https://www.splunk.com',
     'typical_versions': json.dumps(['8.x', '9.x']), 'is_popular': True},

    {'vendor': 'Elastic', 'product_name': 'Elastic Security', 'category': 'SIEM', 'subcategory': 'Security Analytics',
     'common_names': json.dumps(['elastic-security', 'elastic-siem']), 'cpe_vendor': 'elastic', 'cpe_product': 'elastic_security',
     'description': 'SIEM and Endpoint Security', 'website_url': 'https://www.elastic.co',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    {'vendor': 'IBM', 'product_name': 'QRadar', 'category': 'SIEM', 'subcategory': 'Security Intelligence',
     'common_names': json.dumps(['qradar']), 'cpe_vendor': 'ibm', 'cpe_product': 'qradar_security_information_and_event_manager',
     'description': 'Security Information and Event Management', 'website_url': 'https://www.ibm.com/qradar',
     'typical_versions': json.dumps(['7.x']), 'is_popular': True},

    {'vendor': 'Tenable', 'product_name': 'Nessus', 'category': 'Security', 'subcategory': 'Vulnerability Scanner',
     'common_names': json.dumps(['nessus', 'tenable']), 'cpe_vendor': 'tenable', 'cpe_product': 'nessus',
     'description': 'Vulnerability Assessment Scanner', 'website_url': 'https://www.tenable.com',
     'typical_versions': json.dumps(['10.x']), 'is_popular': True},

    {'vendor': 'Qualys', 'product_name': 'Qualys VMDR', 'category': 'Security', 'subcategory': 'Vulnerability Management',
     'common_names': json.dumps(['qualys']), 'cpe_vendor': 'qualys', 'cpe_product': 'qualys_cloud_platform',
     'description': 'Vulnerability Management Detection Response', 'website_url': 'https://www.qualys.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Rapid7', 'product_name': 'InsightVM', 'category': 'Security', 'subcategory': 'Vulnerability Management',
     'common_names': json.dumps(['rapid7', 'insightvm', 'nexpose']), 'cpe_vendor': 'rapid7', 'cpe_product': 'insightvm',
     'description': 'Vulnerability Risk Management', 'website_url': 'https://www.rapid7.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    # ==================== IDENTITY & ACCESS MANAGEMENT ====================
    {'vendor': 'Okta', 'product_name': 'Okta', 'category': 'IAM', 'subcategory': 'Identity Provider',
     'common_names': json.dumps(['okta']), 'cpe_vendor': 'okta', 'cpe_product': 'okta',
     'description': 'Identity and Access Management', 'website_url': 'https://www.okta.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Azure AD', 'category': 'IAM', 'subcategory': 'Identity Provider',
     'common_names': json.dumps(['azure-ad', 'aad', 'entra-id']), 'cpe_vendor': 'microsoft', 'cpe_product': 'azure_active_directory',
     'description': 'Cloud Identity Service', 'website_url': 'https://azure.microsoft.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Ping Identity', 'product_name': 'PingFederate', 'category': 'IAM', 'subcategory': 'Federation Server',
     'common_names': json.dumps(['pingfederate', 'ping']), 'cpe_vendor': 'pingidentity', 'cpe_product': 'pingfederate',
     'description': 'Enterprise Federation Server', 'website_url': 'https://www.pingidentity.com',
     'typical_versions': json.dumps(['11.x', '12.x']), 'is_popular': True},

    {'vendor': 'CyberArk', 'product_name': 'Privileged Access Manager', 'category': 'IAM', 'subcategory': 'PAM',
     'common_names': json.dumps(['cyberark', 'pam']), 'cpe_vendor': 'cyberark', 'cpe_product': 'privileged_access_manager',
     'description': 'Privileged Access Security', 'website_url': 'https://www.cyberark.com',
     'typical_versions': json.dumps(['12.x', '13.x']), 'is_popular': True},

    {'vendor': 'BeyondTrust', 'product_name': 'Password Safe', 'category': 'IAM', 'subcategory': 'PAM',
     'common_names': json.dumps(['beyondtrust', 'password-safe']), 'cpe_vendor': 'beyondtrust', 'cpe_product': 'password_safe',
     'description': 'Enterprise Password Management', 'website_url': 'https://www.beyondtrust.com',
     'typical_versions': json.dumps(['22.x', '23.x']), 'is_popular': True},

    {'vendor': 'Keycloak', 'product_name': 'Keycloak', 'category': 'IAM', 'subcategory': 'Identity Provider',
     'common_names': json.dumps(['keycloak']), 'cpe_vendor': 'redhat', 'cpe_product': 'keycloak',
     'description': 'Open Source Identity Management', 'website_url': 'https://www.keycloak.org',
     'typical_versions': json.dumps(['21.x', '22.x', '23.x']), 'is_popular': True},

    # ==================== COLLABORATION ====================
    {'vendor': 'Slack', 'product_name': 'Slack', 'category': 'Collaboration', 'subcategory': 'Team Messaging',
     'common_names': json.dumps(['slack']), 'cpe_vendor': 'slack', 'cpe_product': 'slack',
     'description': 'Team Communication Platform', 'website_url': 'https://slack.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Microsoft', 'product_name': 'Teams', 'category': 'Collaboration', 'subcategory': 'Team Messaging',
     'common_names': json.dumps(['teams', 'ms-teams']), 'cpe_vendor': 'microsoft', 'cpe_product': 'teams',
     'description': 'Team Collaboration Hub', 'website_url': 'https://www.microsoft.com/teams',
     'typical_versions': json.dumps(['Cloud', 'Desktop']), 'is_popular': True},

    {'vendor': 'Zoom', 'product_name': 'Zoom', 'category': 'Collaboration', 'subcategory': 'Video Conferencing',
     'common_names': json.dumps(['zoom']), 'cpe_vendor': 'zoom', 'cpe_product': 'zoom',
     'description': 'Video Communications Platform', 'website_url': 'https://zoom.us',
     'typical_versions': json.dumps(['5.x']), 'is_popular': True},

    {'vendor': 'Cisco', 'product_name': 'Webex', 'category': 'Collaboration', 'subcategory': 'Video Conferencing',
     'common_names': json.dumps(['webex']), 'cpe_vendor': 'cisco', 'cpe_product': 'webex_meetings',
     'description': 'Video Conferencing and Collaboration', 'website_url': 'https://www.webex.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Mattermost', 'product_name': 'Mattermost', 'category': 'Collaboration', 'subcategory': 'Team Messaging',
     'common_names': json.dumps(['mattermost']), 'cpe_vendor': 'mattermost', 'cpe_product': 'mattermost',
     'description': 'Open Source Team Messaging', 'website_url': 'https://mattermost.com',
     'typical_versions': json.dumps(['7.x', '8.x', '9.x']), 'is_popular': True},

    # ==================== ERP & BUSINESS ====================
    {'vendor': 'SAP', 'product_name': 'SAP S/4HANA', 'category': 'ERP', 'subcategory': 'Enterprise Resource Planning',
     'common_names': json.dumps(['sap', 's4hana']), 'cpe_vendor': 'sap', 'cpe_product': 's4hana',
     'description': 'Intelligent ERP System', 'website_url': 'https://www.sap.com',
     'typical_versions': json.dumps(['2020', '2021', '2022', '2023']), 'is_popular': True},

    {'vendor': 'SAP', 'product_name': 'SAP NetWeaver', 'category': 'ERP', 'subcategory': 'Application Platform',
     'common_names': json.dumps(['netweaver']), 'cpe_vendor': 'sap', 'cpe_product': 'netweaver',
     'description': 'SAP Technology Platform', 'website_url': 'https://www.sap.com',
     'typical_versions': json.dumps(['7.x']), 'is_popular': True},

    {'vendor': 'Oracle', 'product_name': 'Oracle E-Business Suite', 'category': 'ERP', 'subcategory': 'Enterprise Applications',
     'common_names': json.dumps(['ebs', 'e-business-suite']), 'cpe_vendor': 'oracle', 'cpe_product': 'e-business_suite',
     'description': 'Enterprise Resource Planning Suite', 'website_url': 'https://www.oracle.com',
     'typical_versions': json.dumps(['12.x']), 'is_popular': True},

    {'vendor': 'Oracle', 'product_name': 'PeopleSoft', 'category': 'ERP', 'subcategory': 'HCM/Finance',
     'common_names': json.dumps(['peoplesoft']), 'cpe_vendor': 'oracle', 'cpe_product': 'peoplesoft',
     'description': 'Human Capital and Financial Management', 'website_url': 'https://www.oracle.com',
     'typical_versions': json.dumps(['9.x']), 'is_popular': True},

    {'vendor': 'ServiceNow', 'product_name': 'ServiceNow', 'category': 'ITSM', 'subcategory': 'IT Service Management',
     'common_names': json.dumps(['servicenow', 'snow']), 'cpe_vendor': 'servicenow', 'cpe_product': 'servicenow',
     'description': 'Digital Workflow Platform', 'website_url': 'https://www.servicenow.com',
     'typical_versions': json.dumps(['Tokyo', 'Utah', 'Vancouver']), 'is_popular': True},

    # ==================== API & INTEGRATION ====================
    {'vendor': 'Kong', 'product_name': 'Kong Gateway', 'category': 'API Gateway', 'subcategory': 'API Management',
     'common_names': json.dumps(['kong']), 'cpe_vendor': 'konghq', 'cpe_product': 'kong',
     'description': 'Cloud-Native API Gateway', 'website_url': 'https://konghq.com',
     'typical_versions': json.dumps(['3.x']), 'is_popular': True},

    {'vendor': 'MuleSoft', 'product_name': 'Anypoint Platform', 'category': 'Integration', 'subcategory': 'iPaaS',
     'common_names': json.dumps(['mulesoft', 'anypoint']), 'cpe_vendor': 'mulesoft', 'cpe_product': 'anypoint_platform',
     'description': 'Integration Platform as a Service', 'website_url': 'https://www.mulesoft.com',
     'typical_versions': json.dumps(['Cloud']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'APISIX', 'category': 'API Gateway', 'subcategory': 'API Management',
     'common_names': json.dumps(['apisix']), 'cpe_vendor': 'apache', 'cpe_product': 'apisix',
     'description': 'Dynamic API Gateway', 'website_url': 'https://apisix.apache.org',
     'typical_versions': json.dumps(['3.x']), 'is_popular': False},

    # ==================== MORE DATABASES ====================
    {'vendor': 'Oracle', 'product_name': 'Oracle Database', 'category': 'Database', 'subcategory': 'Enterprise RDBMS',
     'common_names': json.dumps(['oracle', 'oracle-db']), 'cpe_vendor': 'oracle', 'cpe_product': 'database_server',
     'description': 'Enterprise Relational Database', 'website_url': 'https://www.oracle.com/database',
     'typical_versions': json.dumps(['19c', '21c', '23c']), 'is_popular': True},

    {'vendor': 'IBM', 'product_name': 'Db2', 'category': 'Database', 'subcategory': 'Enterprise RDBMS',
     'common_names': json.dumps(['db2', 'ibm-db2']), 'cpe_vendor': 'ibm', 'cpe_product': 'db2',
     'description': 'Enterprise Database Server', 'website_url': 'https://www.ibm.com/db2',
     'typical_versions': json.dumps(['11.x']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'Cassandra', 'category': 'Database', 'subcategory': 'NoSQL Database',
     'common_names': json.dumps(['cassandra']), 'cpe_vendor': 'apache', 'cpe_product': 'cassandra',
     'description': 'Distributed NoSQL Database', 'website_url': 'https://cassandra.apache.org',
     'typical_versions': json.dumps(['4.x']), 'is_popular': True},

    {'vendor': 'CouchDB', 'product_name': 'CouchDB', 'category': 'Database', 'subcategory': 'NoSQL Database',
     'common_names': json.dumps(['couchdb']), 'cpe_vendor': 'apache', 'cpe_product': 'couchdb',
     'description': 'Document-Oriented NoSQL Database', 'website_url': 'https://couchdb.apache.org',
     'typical_versions': json.dumps(['3.x']), 'is_popular': False},

    {'vendor': 'InfluxData', 'product_name': 'InfluxDB', 'category': 'Database', 'subcategory': 'Time Series',
     'common_names': json.dumps(['influxdb']), 'cpe_vendor': 'influxdata', 'cpe_product': 'influxdb',
     'description': 'Time Series Database', 'website_url': 'https://www.influxdata.com',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'TimescaleDB', 'product_name': 'TimescaleDB', 'category': 'Database', 'subcategory': 'Time Series',
     'common_names': json.dumps(['timescaledb']), 'cpe_vendor': 'timescale', 'cpe_product': 'timescaledb',
     'description': 'Time Series Database on PostgreSQL', 'website_url': 'https://www.timescale.com',
     'typical_versions': json.dumps(['2.x']), 'is_popular': False},

    # ==================== APPLICATION FRAMEWORKS ====================
    {'vendor': 'Spring', 'product_name': 'Spring Framework', 'category': 'Framework', 'subcategory': 'Java Framework',
     'common_names': json.dumps(['spring', 'spring-framework']), 'cpe_vendor': 'vmware', 'cpe_product': 'spring_framework',
     'description': 'Java Application Framework', 'website_url': 'https://spring.io',
     'typical_versions': json.dumps(['5.x', '6.x']), 'is_popular': True},

    {'vendor': 'Spring', 'product_name': 'Spring Boot', 'category': 'Framework', 'subcategory': 'Java Framework',
     'common_names': json.dumps(['spring-boot']), 'cpe_vendor': 'vmware', 'cpe_product': 'spring_boot',
     'description': 'Java Application Framework', 'website_url': 'https://spring.io/projects/spring-boot',
     'typical_versions': json.dumps(['2.x', '3.x']), 'is_popular': True},

    {'vendor': 'Django', 'product_name': 'Django', 'category': 'Framework', 'subcategory': 'Python Framework',
     'common_names': json.dumps(['django']), 'cpe_vendor': 'djangoproject', 'cpe_product': 'django',
     'description': 'Python Web Framework', 'website_url': 'https://www.djangoproject.com',
     'typical_versions': json.dumps(['4.x', '5.x']), 'is_popular': True},

    {'vendor': 'Ruby on Rails', 'product_name': 'Rails', 'category': 'Framework', 'subcategory': 'Ruby Framework',
     'common_names': json.dumps(['rails', 'ruby-on-rails']), 'cpe_vendor': 'rubyonrails', 'cpe_product': 'rails',
     'description': 'Ruby Web Application Framework', 'website_url': 'https://rubyonrails.org',
     'typical_versions': json.dumps(['6.x', '7.x']), 'is_popular': True},

    {'vendor': 'Laravel', 'product_name': 'Laravel', 'category': 'Framework', 'subcategory': 'PHP Framework',
     'common_names': json.dumps(['laravel']), 'cpe_vendor': 'laravel', 'cpe_product': 'laravel',
     'description': 'PHP Web Framework', 'website_url': 'https://laravel.com',
     'typical_versions': json.dumps(['9.x', '10.x', '11.x']), 'is_popular': True},

    {'vendor': 'Express', 'product_name': 'Express.js', 'category': 'Framework', 'subcategory': 'Node.js Framework',
     'common_names': json.dumps(['express', 'expressjs']), 'cpe_vendor': 'expressjs', 'cpe_product': 'express',
     'description': 'Node.js Web Framework', 'website_url': 'https://expressjs.com',
     'typical_versions': json.dumps(['4.x']), 'is_popular': True},

    {'vendor': 'React', 'product_name': 'React', 'category': 'Framework', 'subcategory': 'JavaScript Library',
     'common_names': json.dumps(['react', 'reactjs']), 'cpe_vendor': 'facebook', 'cpe_product': 'react',
     'description': 'JavaScript Library for UI', 'website_url': 'https://react.dev',
     'typical_versions': json.dumps(['17.x', '18.x']), 'is_popular': True},

    {'vendor': 'Vue.js', 'product_name': 'Vue.js', 'category': 'Framework', 'subcategory': 'JavaScript Framework',
     'common_names': json.dumps(['vue', 'vuejs']), 'cpe_vendor': 'vuejs', 'cpe_product': 'vue.js',
     'description': 'Progressive JavaScript Framework', 'website_url': 'https://vuejs.org',
     'typical_versions': json.dumps(['2.x', '3.x']), 'is_popular': True},

    {'vendor': 'Angular', 'product_name': 'Angular', 'category': 'Framework', 'subcategory': 'JavaScript Framework',
     'common_names': json.dumps(['angular']), 'cpe_vendor': 'google', 'cpe_product': 'angular',
     'description': 'Web Application Framework', 'website_url': 'https://angular.io',
     'typical_versions': json.dumps(['15.x', '16.x', '17.x']), 'is_popular': True},

    # ==================== REMOTE ACCESS & VDI ====================
    {'vendor': 'Citrix', 'product_name': 'Citrix ADC', 'category': 'Load Balancing', 'subcategory': 'ADC',
     'common_names': json.dumps(['citrix-adc', 'netscaler']), 'cpe_vendor': 'citrix', 'cpe_product': 'application_delivery_controller_firmware',
     'description': 'Application Delivery Controller', 'website_url': 'https://www.citrix.com',
     'typical_versions': json.dumps(['13.x']), 'is_popular': True},

    {'vendor': 'Citrix', 'product_name': 'Citrix Virtual Apps', 'category': 'VDI', 'subcategory': 'Application Virtualization',
     'common_names': json.dumps(['citrix-virtual-apps', 'xenapp']), 'cpe_vendor': 'citrix', 'cpe_product': 'virtual_apps',
     'description': 'Application Virtualization', 'website_url': 'https://www.citrix.com',
     'typical_versions': json.dumps(['7.x']), 'is_popular': True},

    {'vendor': 'VMware', 'product_name': 'Horizon', 'category': 'VDI', 'subcategory': 'Virtual Desktop',
     'common_names': json.dumps(['horizon', 'vmware-horizon']), 'cpe_vendor': 'vmware', 'cpe_product': 'horizon',
     'description': 'Virtual Desktop Infrastructure', 'website_url': 'https://www.vmware.com/products/horizon.html',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    # ==================== STORAGE ====================
    {'vendor': 'NetApp', 'product_name': 'ONTAP', 'category': 'Storage', 'subcategory': 'Enterprise Storage',
     'common_names': json.dumps(['ontap', 'netapp']), 'cpe_vendor': 'netapp', 'cpe_product': 'ontap',
     'description': 'Enterprise Data Management', 'website_url': 'https://www.netapp.com',
     'typical_versions': json.dumps(['9.x']), 'is_popular': True},

    {'vendor': 'Dell EMC', 'product_name': 'PowerStore', 'category': 'Storage', 'subcategory': 'Enterprise Storage',
     'common_names': json.dumps(['powerstore', 'dell-emc']), 'cpe_vendor': 'dell', 'cpe_product': 'powerstore',
     'description': 'Enterprise Storage Array', 'website_url': 'https://www.dell.com',
     'typical_versions': json.dumps(['3.x']), 'is_popular': True},

    {'vendor': 'TrueNAS', 'product_name': 'TrueNAS', 'category': 'Storage', 'subcategory': 'NAS',
     'common_names': json.dumps(['truenas', 'freenas']), 'cpe_vendor': 'ixsystems', 'cpe_product': 'truenas',
     'description': 'Open Source Storage Operating System', 'website_url': 'https://www.truenas.com',
     'typical_versions': json.dumps(['CORE', 'SCALE']), 'is_popular': True},

    {'vendor': 'MinIO', 'product_name': 'MinIO', 'category': 'Storage', 'subcategory': 'Object Storage',
     'common_names': json.dumps(['minio']), 'cpe_vendor': 'minio', 'cpe_product': 'minio',
     'description': 'S3 Compatible Object Storage', 'website_url': 'https://min.io',
     'typical_versions': json.dumps(['RELEASE']), 'is_popular': True},

    {'vendor': 'Ceph', 'product_name': 'Ceph', 'category': 'Storage', 'subcategory': 'Distributed Storage',
     'common_names': json.dumps(['ceph']), 'cpe_vendor': 'redhat', 'cpe_product': 'ceph_storage',
     'description': 'Distributed Storage System', 'website_url': 'https://ceph.io',
     'typical_versions': json.dumps(['17.x', '18.x']), 'is_popular': True},

    # ==================== CLOUD PLATFORMS ====================
    {'vendor': 'HashiCorp', 'product_name': 'Terraform', 'category': 'Infrastructure', 'subcategory': 'IaC',
     'common_names': json.dumps(['terraform']), 'cpe_vendor': 'hashicorp', 'cpe_product': 'terraform',
     'description': 'Infrastructure as Code', 'website_url': 'https://www.terraform.io',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    {'vendor': 'HashiCorp', 'product_name': 'Vault', 'category': 'Security', 'subcategory': 'Secrets Management',
     'common_names': json.dumps(['vault', 'hashicorp-vault']), 'cpe_vendor': 'hashicorp', 'cpe_product': 'vault',
     'description': 'Secrets and Encryption Management', 'website_url': 'https://www.vaultproject.io',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    {'vendor': 'HashiCorp', 'product_name': 'Consul', 'category': 'Infrastructure', 'subcategory': 'Service Discovery',
     'common_names': json.dumps(['consul']), 'cpe_vendor': 'hashicorp', 'cpe_product': 'consul',
     'description': 'Service Networking Platform', 'website_url': 'https://www.consul.io',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    # ==================== MORE WEB SERVERS ====================
    {'vendor': 'Caddy', 'product_name': 'Caddy', 'category': 'Web Server', 'subcategory': 'HTTP Server',
     'common_names': json.dumps(['caddy', 'caddyserver']), 'cpe_vendor': 'caddyserver', 'cpe_product': 'caddy',
     'description': 'Modern Web Server with Automatic HTTPS', 'website_url': 'https://caddyserver.com',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Traefik', 'product_name': 'Traefik', 'category': 'Load Balancing', 'subcategory': 'Cloud Native Proxy',
     'common_names': json.dumps(['traefik']), 'cpe_vendor': 'traefik', 'cpe_product': 'traefik',
     'description': 'Cloud Native Edge Router', 'website_url': 'https://traefik.io',
     'typical_versions': json.dumps(['2.x', '3.x']), 'is_popular': True},

    {'vendor': 'Envoy', 'product_name': 'Envoy', 'category': 'Load Balancing', 'subcategory': 'Service Proxy',
     'common_names': json.dumps(['envoy', 'envoy-proxy']), 'cpe_vendor': 'envoyproxy', 'cpe_product': 'envoy',
     'description': 'Cloud Native High Performance Proxy', 'website_url': 'https://www.envoyproxy.io',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    # ==================== LOGGING ====================
    {'vendor': 'Graylog', 'product_name': 'Graylog', 'category': 'Logging', 'subcategory': 'Log Management',
     'common_names': json.dumps(['graylog']), 'cpe_vendor': 'graylog', 'cpe_product': 'graylog',
     'description': 'Log Management Platform', 'website_url': 'https://www.graylog.org',
     'typical_versions': json.dumps(['5.x']), 'is_popular': True},

    {'vendor': 'Fluentd', 'product_name': 'Fluentd', 'category': 'Logging', 'subcategory': 'Data Collector',
     'common_names': json.dumps(['fluentd', 'td-agent']), 'cpe_vendor': 'fluentd', 'cpe_product': 'fluentd',
     'description': 'Open Source Data Collector', 'website_url': 'https://www.fluentd.org',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    {'vendor': 'Elastic', 'product_name': 'Logstash', 'category': 'Logging', 'subcategory': 'Data Pipeline',
     'common_names': json.dumps(['logstash']), 'cpe_vendor': 'elastic', 'cpe_product': 'logstash',
     'description': 'Server-Side Data Processing Pipeline', 'website_url': 'https://www.elastic.co/logstash',
     'typical_versions': json.dumps(['7.x', '8.x']), 'is_popular': True},

    # ==================== ADDITIONAL POPULAR SOFTWARE ====================
    {'vendor': 'Apache', 'product_name': 'Struts', 'category': 'Framework', 'subcategory': 'Java Framework',
     'common_names': json.dumps(['struts', 'apache-struts']), 'cpe_vendor': 'apache', 'cpe_product': 'struts',
     'description': 'Java Web Application Framework', 'website_url': 'https://struts.apache.org',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'Log4j', 'category': 'Library', 'subcategory': 'Logging',
     'common_names': json.dumps(['log4j', 'log4j2']), 'cpe_vendor': 'apache', 'cpe_product': 'log4j',
     'description': 'Java Logging Library', 'website_url': 'https://logging.apache.org/log4j',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Apache', 'product_name': 'ActiveMQ', 'category': 'Message Queue', 'subcategory': 'Message Broker',
     'common_names': json.dumps(['activemq']), 'cpe_vendor': 'apache', 'cpe_product': 'activemq',
     'description': 'Open Source Message Broker', 'website_url': 'https://activemq.apache.org',
     'typical_versions': json.dumps(['5.x']), 'is_popular': True},

    {'vendor': 'SonarSource', 'product_name': 'SonarQube', 'category': 'DevOps', 'subcategory': 'Code Quality',
     'common_names': json.dumps(['sonarqube', 'sonar']), 'cpe_vendor': 'sonarsource', 'cpe_product': 'sonarqube',
     'description': 'Code Quality Platform', 'website_url': 'https://www.sonarqube.org',
     'typical_versions': json.dumps(['9.x', '10.x']), 'is_popular': True},

    {'vendor': 'Artifactory', 'product_name': 'JFrog Artifactory', 'category': 'DevOps', 'subcategory': 'Artifact Repository',
     'common_names': json.dumps(['artifactory', 'jfrog']), 'cpe_vendor': 'jfrog', 'cpe_product': 'artifactory',
     'description': 'Universal Artifact Repository', 'website_url': 'https://jfrog.com/artifactory',
     'typical_versions': json.dumps(['7.x']), 'is_popular': True},

    {'vendor': 'Nexus', 'product_name': 'Nexus Repository', 'category': 'DevOps', 'subcategory': 'Artifact Repository',
     'common_names': json.dumps(['nexus', 'nexus-repository']), 'cpe_vendor': 'sonatype', 'cpe_product': 'nexus_repository_manager',
     'description': 'Repository Manager', 'website_url': 'https://www.sonatype.com/nexus',
     'typical_versions': json.dumps(['3.x']), 'is_popular': True},

    {'vendor': 'Portainer', 'product_name': 'Portainer', 'category': 'Containerization', 'subcategory': 'Container Management',
     'common_names': json.dumps(['portainer']), 'cpe_vendor': 'portainer', 'cpe_product': 'portainer',
     'description': 'Container Management UI', 'website_url': 'https://www.portainer.io',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Argo', 'product_name': 'ArgoCD', 'category': 'CI/CD', 'subcategory': 'GitOps',
     'common_names': json.dumps(['argocd', 'argo-cd']), 'cpe_vendor': 'argoproj', 'cpe_product': 'argo-cd',
     'description': 'GitOps Continuous Delivery', 'website_url': 'https://argoproj.github.io/cd',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'Harbor', 'product_name': 'Harbor', 'category': 'Containerization', 'subcategory': 'Container Registry',
     'common_names': json.dumps(['harbor']), 'cpe_vendor': 'goharbor', 'cpe_product': 'harbor',
     'description': 'Container Image Registry', 'website_url': 'https://goharbor.io',
     'typical_versions': json.dumps(['2.x']), 'is_popular': True},

    {'vendor': 'AWX', 'product_name': 'AWX', 'category': 'Configuration Management', 'subcategory': 'Automation',
     'common_names': json.dumps(['awx', 'ansible-tower']), 'cpe_vendor': 'redhat', 'cpe_product': 'ansible_tower',
     'description': 'Ansible Tower Open Source', 'website_url': 'https://github.com/ansible/awx',
     'typical_versions': json.dumps(['21.x', '22.x', '23.x']), 'is_popular': True},

    {'vendor': 'Istio', 'product_name': 'Istio', 'category': 'Orchestration', 'subcategory': 'Service Mesh',
     'common_names': json.dumps(['istio']), 'cpe_vendor': 'istio', 'cpe_product': 'istio',
     'description': 'Service Mesh Platform', 'website_url': 'https://istio.io',
     'typical_versions': json.dumps(['1.x']), 'is_popular': True},

    {'vendor': 'Linkerd', 'product_name': 'Linkerd', 'category': 'Orchestration', 'subcategory': 'Service Mesh',
     'common_names': json.dumps(['linkerd']), 'cpe_vendor': 'linkerd', 'cpe_product': 'linkerd',
     'description': 'Ultralight Service Mesh', 'website_url': 'https://linkerd.io',
     'typical_versions': json.dumps(['2.x']), 'is_popular': False},
]

def seed_catalog():
    """Seed the service catalog with comprehensive data"""
    app = create_app()

    with app.app_context():
        print("Seeding service catalog...")
        print(f"Total services to add: {len(SERVICE_CATALOG)}")

        added_count = 0
        skipped_count = 0

        for service_data in SERVICE_CATALOG:
            # Check if service already exists
            existing = ServiceCatalog.query.filter_by(
                vendor=service_data['vendor'],
                product_name=service_data['product_name']
            ).first()

            if existing:
                skipped_count += 1
                continue

            # Create new service catalog entry
            service = ServiceCatalog(**service_data)
            db.session.add(service)
            added_count += 1

        try:
            db.session.commit()
            print(f"\n✓ Service catalog seeded successfully!")
            print(f"  Added: {added_count}")
            print(f"  Skipped (already exist): {skipped_count}")
            print(f"  Total in catalog: {ServiceCatalog.query.count()}")

            # Show category breakdown
            print("\nCategory breakdown:")
            categories = db.session.query(
                ServiceCatalog.category,
                db.func.count(ServiceCatalog.id).label('count')
            ).group_by(ServiceCatalog.category).all()

            for category, count in sorted(categories, key=lambda x: x[1], reverse=True):
                print(f"  {category}: {count}")

        except Exception as e:
            print(f"\n❌ Error seeding catalog: {str(e)}")
            db.session.rollback()
            return 1

    return 0

if __name__ == '__main__':
    sys.exit(seed_catalog())
