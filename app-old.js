// 啟動伺服器
app.listen(port, () => {
  console.log(`🚀 混合版本伺服器啟動！`);
  console.log(`🌐 訪問: http://localhost:${port}`);
  console.log(`✅ 健康檢查: http://localhost:${port}/health`);
  console.log(`📚 API 文檔: http://localhost:${port}/api-docs`);
  console.log(`🔑 註冊端點: POST http://localhost:${port}${API_PREFIX}/auth/register`);
  console.log(`🔑 登入端點: POST http://localhost:${port}${API_PREFIX}/auth/login`);
  console.log(`\n📝 必需環境變數:`);
  console.log(`   JWT_SECRET=你的密鑰`);
  console.log(`   DATABASE_URL=PostgreSQL連接字串`);
  console.log(`   (Zeabur 會自動提供 DATABASE_URL)`);
});