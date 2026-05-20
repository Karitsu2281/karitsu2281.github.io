control 'fw-01' do
  impact 1.0
  title 'iptables debe estar instalado'
  desc 'El firewall iptables debe estar presente'
  describe package('iptables') do
    it { should be_installed }
  end
end

control 'fw-02' do
  impact 1.0
  title 'La politica por defecto de INPUT debe ser DROP'
  desc 'El trafico entrante no solicitado debe ser denegado por defecto'
  describe iptables do
    it { should have_rule('-P INPUT DROP') }
  end
end

control 'fw-03' do
  impact 1.0
  title 'La politica por defecto de FORWARD debe ser DROP'
  desc 'El forwarding no autorizado debe ser denegado'
  describe iptables do
    it { should have_rule('-P FORWARD DROP') }
  end
end

control 'fw-04' do
  impact 0.8
  title 'El trafico loopback debe estar permitido'
  desc 'La interfaz lo debe aceptar todo el trafico'
  describe iptables do
    it { should have_rule('-A INPUT -i lo -j ACCEPT') }
  end
end

control 'fw-05' do
  impact 0.8
  title 'Las conexiones establecidas deben estar permitidas'
  desc 'El trafico de conexiones ya establecidas debe aceptarse'
  describe iptables do
    it { should have_rule('-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT') }
  end
end

control 'fw-06' do
  impact 0.8
  title 'Debe existir rate limiting para SSH'
  desc 'Debe haber reglas de limitacion de intentos SSH'
  describe iptables do
    it { should have_rule('-A INPUT -p tcp -m tcp --dport 22 -m state --state NEW -m recent --set') }
  end
end

control 'fw-07' do
  impact 0.7
  title 'Debe existir logging de paquetes descartados'
  desc 'Los paquetes denegados deben registrarse en los logs'
  describe iptables do
    it { should have_rule('-A INPUT -j LOG') }
  end
end

control 'fw-08' do
  impact 0.7
  title 'Los puertos 80 y 443 deben estar abiertos'
  desc 'El servidor web debe ser accesible'
  describe port(80) do
    it { should be_listening }
    its('protocols') { should include 'tcp' }
  end
  describe port(443) do
    it { should be_listening }
    its('protocols') { should include 'tcp' }
  end
end
