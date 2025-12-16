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
