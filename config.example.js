// ===== CONFIGURAÇÃO DO SITE eFOOTBALL BRASIL =====
// Copie este arquivo para js/config.js e preencha com seus dados

window.SITE_CONFIG = {
  // URL do backend Node.js (ex: 'https://efootball-api.onrender.com')
  // Deixe VAZIO '' se o backend estiver no mesmo domínio
  API_BASE: 'https://SEU-BACKEND.onrender.com',

  // Caminho base do site no GitHub Pages
  // Se o repositório é 'username/efootball-brasil', use '/efootball-brasil'
  // Se for 'username.github.io', deixe ''
  BASE_PATH: '/efootball-brasil',

  // URL do WebSocket do backend (para chat em tempo real)
  // Ex: 'wss://SEU-BACKEND.onrender.com'
  // Deixe VAZIO '' para usar o mesmo host da API_BASE
  WS_URL: 'wss://SEU-BACKEND.onrender.com',

  DISCORD_CLIENT_ID: 'SEU_CLIENT_ID_AQUI',
  DISCORD_REDIRECT_URI: window.location.origin + '/login-discord.html',
  DISCORD_API: 'https://discord.com/api',

  PIX: {
    chave: 'efootball@vip.com.br',
    nome: 'eFootball Brasil VIP'
  },

  SERVER: {
    nome: 'eFootball Brasil',
    id: '1077324994373222500',
    convite: 'https://discord.gg/efootballbrasil'
  },

  STORE_ITEMS: [
    {
      id: 'vip-bronze',
      name: 'VIP Bronze',
      desc: 'Acesso básico aos recursos VIP',
      price: 9.90,
      icon: '🥉',
      features: ['Tag VIP no servidor', 'Cargo exclusivo', 'Acesso a sala VIP'],
      featured: false
    },
    {
      id: 'vip-silver',
      name: 'VIP Prata',
      desc: 'Experiência VIP intermediária',
      price: 19.90,
      icon: '🥈',
      features: ['Tudo do Bronze', 'Moedas extras (500)', 'Suporte prioritário', 'Comandos exclusivos'],
      featured: false
    },
    {
      id: 'vip-gold',
      name: 'VIP Ouro',
      desc: 'A experiência VIP completa',
      price: 39.90,
      icon: '🥇',
      features: ['Tudo do Prata', 'Moedas extras (1500)', 'Sorteios exclusivos', 'Acesso antecipado', 'Badge especial'],
      featured: true
    },
    {
      id: 'vip-diamond',
      name: 'VIP Diamante',
      desc: 'O ápice do VIP',
      price: 79.90,
      icon: '💎',
      features: ['Tudo do Ouro', 'Moedas extras (5000)', 'Staff dedicado', 'Personalização', 'Todos os benefícios'],
      featured: false
    }
  ]
};
