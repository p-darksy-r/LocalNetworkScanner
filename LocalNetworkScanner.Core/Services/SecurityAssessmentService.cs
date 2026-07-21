using LocalNetworkScanner.Core.Models;

namespace LocalNetworkScanner.Core.Services;

public sealed class SecurityAssessmentService
{
    public void Assess(NetworkDevice device)
    {
        List<string> findings = [];
        HashSet<int> ports = device.Ports.Select(item => item.Port).ToHashSet();
        int score = 0;

        AddIfOpen(21, 18, "FTP transmite credenciais sem cifragem; prefere SFTP/FTPS.");
        AddIfOpen(23, 45, "Telnet está exposto e não cifra a sessão.");
        AddIfOpen(445, 20, "SMB está acessível; confirma atualizações e restringe o acesso à LAN.");
        AddIfOpen(3389, 20, "RDP está acessível; usa NLA, MFA/VPN e regras de firewall.");
        AddIfOpen(5900, 25, "VNC está acessível; confirma cifragem e autenticação forte.");
        AddIfOpen(2375, 60, "Docker API sem TLS pode permitir controlo total do host.");
        AddIfOpen(6379, 45, "Redis está acessível; não deve ficar sem autenticação/ACL.");
        AddIfOpen(9200, 40, "Elasticsearch está acessível; valida autenticação e exposição de dados.");
        AddIfOpen(27017, 40, "MongoDB está acessível; valida autenticação e bind de rede.");

        foreach (PortScanResult port in device.Ports)
        {
            if (port.CertificateExpiresAt.HasValue && port.CertificateExpiresAt < DateTimeOffset.Now)
            {
                findings.Add($"Certificado TLS expirado na porta {port.Port}.");
                score += 25;
            }
            else if (port.CertificateExpiresAt.HasValue &&
                     port.CertificateExpiresAt < DateTimeOffset.Now.AddDays(30))
            {
                findings.Add($"Certificado TLS na porta {port.Port} expira em menos de 30 dias.");
                score += 10;
            }
        }

        device.SecurityFindings = findings;
        device.RiskScore = Math.Min(100, score);
        device.RiskLevel = device.RiskScore >= 40
            ? "Alto"
            : device.RiskScore >= 15
                ? "Médio"
                : "Baixo";

        return;

        void AddIfOpen(int port, int weight, string message)
        {
            if (ports.Contains(port))
            {
                findings.Add($"Porta {port}: {message}");
                score += weight;
            }
        }
    }
}
