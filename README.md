# DNS-analyser

O sistema de resolução de nomes da Internet, o Domain Name System (DNS),
tradicionalmente opera sobre UDP na porta 53, sem criptografia. As consultas DNS
percorrem a rede em texto claro, o que permite a intermediários, como provedores de
acesso (ISPs), administradores de rede e serviços de DNS público, observar, interceptar e
até manipular as respostas.
Diversos provedores de DNS público oferecem servidores com diferentes políticas de
filtragem: alguns bloqueiam domínios associados a malware e phishing, outros bloqueiam
conteúdo adulto, e alguns não aplicam nenhum filtro. Já os ISPs brasileiros operam
servidores DNS recursivos que podem aplicar bloqueios por determinação judicial.
O aumento das preocupações com privacidade e segurança levou ao desenvolvimento de
versões criptografadas do DNS:
• DNS over TLS (DoT) - DNS criptografado sobre TLS, porta 853 (RFC 7858)
• DNS over HTTPS (DoH) - DNS encapsulado em HTTPS, porta 443 (RFC 8484)
Isso significa que a resposta para uma mesma consulta DNS pode variar conforme o
servidor utilizado, e que a visibilidade do tráfego depende do protocolo utilizado, o
que levanta questões importantes sobre censura, transparência e privacidade na Internet.
