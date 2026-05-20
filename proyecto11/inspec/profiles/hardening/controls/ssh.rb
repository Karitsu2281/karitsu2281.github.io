control 'ssh-01' do
  impact 1.0
  title 'SSH debe estar instalado y corriendo'
  desc 'Verifica que el servicio SSH este activo'
  describe service('ssh') do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end
end

control 'ssh-02' do
  impact 1.0
  title 'SSH debe denegar el acceso root'
  desc 'PermitRootLogin debe estar configurado como no'
  describe sshd_config do
    its('PermitRootLogin') { should cmp 'no' }
  end
end

control 'ssh-03' do
  impact 1.0
  title 'SSH debe deshabilitar la autenticacion por password'
  desc 'PasswordAuthentication debe estar configurado como no'
  describe sshd_config do
    its('PasswordAuthentication') { should cmp 'no' }
  end
end

control 'ssh-04' do
  impact 0.8
  title 'SSH debe deshabilitar el reenvio X11'
  desc 'X11Forwarding debe estar configurado como no'
  describe sshd_config do
    its('X11Forwarding') { should cmp 'no' }
  end
end

control 'ssh-05' do
  impact 0.8
  title 'SSH debe limitar los intentos de autenticacion'
  desc 'MaxAuthTries debe ser menor o igual a 3'
  describe sshd_config do
    its('MaxAuthTries') { should cmp <= 3 }
  end
end

control 'ssh-06' do
  impact 0.8
  title 'SSH debe usar ciphers seguros'
  desc 'Los ciphers deben ser algoritmos fuertes'
  describe sshd_config do
    its('Ciphers') { should match /aes256-ctr/ }
  end
end

control 'ssh-07' do
  impact 0.8
  title 'SSH debe usar MACs seguros'
  desc 'Los MACs deben ser HMAC-SHA2'
  describe sshd_config do
    its('MACs') { should match /hmac-sha2/ }
  end
end

control 'ssh-08' do
  impact 0.7
  title 'SSH debe tener un banner de advertencia'
  desc 'Debe existir un banner en /etc/issue.net'
  describe file('/etc/issue.net') do
    it { should exist }
    it { should be_file }
  end
end
