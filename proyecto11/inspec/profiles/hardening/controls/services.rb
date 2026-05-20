control 'svc-01' do
  impact 0.8
  title 'El servicio rsyslog debe estar corriendo'
  desc 'El logging remoto debe estar activo'
  describe service('rsyslog') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'svc-02' do
  impact 0.8
  title 'El servicio auditd debe estar activo'
  desc 'El sistema de auditoria debe estar en ejecucion'
  describe service('auditd') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'svc-03' do
  impact 0.7
  title 'Los servicios inseguros deben estar deshabilitados'
  desc 'Servicios como telnet, rsh, etc. no deben estar presentes'
  describe package('telnetd') do
    it { should_not be_installed }
  end
end

control 'svc-04' do
  impact 0.7
  title 'fail2ban debe estar instalado y corriendo'
  desc 'El sistema de prevencion de intrusiones debe activo'
  describe package('fail2ban') do
    it { should be_installed }
  end
end

control 'svc-05' do
  impact 0.7
  title 'Los servicios de red inseguros deben estar deshabilitados'
  desc 'avahi-daemon, cups, nfs no deben estar corriendo'
  %w[avahi-daemon cups cups-browsed nfs-common rpcbind].each do |svc|
    describe service(svc) do
      it { should_not be_running }
      it { should_not be_enabled }
    end
  end
end

control 'svc-06' do
  impact 0.7
  title 'Los permisos de archivos sensibles deben ser seguros'
  desc '/etc/passwd, /etc/shadow y otros deben tener permisos restrictivos'
  describe file('/etc/passwd') do
    it { should exist }
    it { should be_readable }
    its('mode') { should cmp '0644' }
  end
  describe file('/etc/shadow') do
    it { should exist }
    its('mode') { should cmp '0600' }
  end
end

control 'svc-07' do
  impact 0.8
  title 'Los parametros del kernel deben estar seguros'
  desc 'Parametros sysctl de hardening deben estar aplicados'
  describe kernel_parameter('net.ipv4.ip_forward') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.all.send_redirects') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.conf.all.accept_source_route') do
    its('value') { should eq 0 }
  end
  describe kernel_parameter('net.ipv4.tcp_syncookies') do
    its('value') { should eq 1 }
  end
  describe kernel_parameter('kernel.randomize_va_space') do
    its('value') { should eq 2 }
  end
end

control 'svc-08' do
  impact 0.6
  title 'Los modulos del kernel no utilizados deben estar en blacklist'
  desc 'Modulos como cramfs, usb-storage deben estar deshabilitados'
  describe file('/etc/modprobe.d/blacklist.conf') do
    it { should exist }
    its('content') { should match /install cramfs \/bin\/true/ }
    its('content') { should match /install usb-storage \/bin\/true/ }
  end
end
