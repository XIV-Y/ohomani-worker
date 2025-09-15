/**
 * パスワードをハッシュ化
 */
export async function hashPassword(password: string, salt: string): Promise<string> {
  const saltedPassword = salt + password;
  const encoder = new TextEncoder();
  const data = encoder.encode(saltedPassword);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

/**
 * 保存されたパスワードを検証
 */
export async function verifyPassword(inputPassword: string, storedValue: string): Promise<boolean> {
  try {
    const [salt, originalHash] = storedValue.split(':');
    if (!salt || !originalHash) {
      return false;
    }
    const inputHash = await hashPassword(inputPassword, salt);
    return inputHash === originalHash;
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

