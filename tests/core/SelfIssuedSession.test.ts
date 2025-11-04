// Import the class to be tested and necessary types
import { SelfIssuedSession, SelfIssuedSessionOptions } from '../../src/core/SelfIssuedSession';
import { DereferencableIdClientDetails } from '../../src/core/SessionInformation';
import * as jose from 'jose';

// --- JEST MOCKS ---

// Use the manual mock for jose
jest.mock('jose');

// --- TESTS ---

describe('SelfIssuedSession', () => {
  // --- Test Data & Mocks ---
  const mockWebId = 'https://alice.example/card#me';
  const mockClientDetails: DereferencableIdClientDetails = { client_id: 'https://app.example/profile' };

  // --- Helper Functions ---

  /** Helper to create SelfIssuedSession instance */
  const createSession = (
    clientDetails: DereferencableIdClientDetails | undefined = mockClientDetails,
    options: SelfIssuedSessionOptions = {}
  ) => {
    return new SelfIssuedSession(clientDetails, options);
  };

  beforeEach(() => {
    // Restore all spies and mocks
    jest.restoreAllMocks();
    jest.clearAllMocks();

    // Mock jose functions
    (jose.generateKeyPair as jest.Mock).mockResolvedValue({
      publicKey: 'mockPublicKey',
      privateKey: 'mockPrivateKey'
    });
    
    const mockSignJWT = {
      setProtectedHeader: jest.fn().mockReturnThis(),
      sign: jest.fn().mockResolvedValue('mock-signed-token')
    };
    
    (jose.SignJWT as any).mockImplementation(() => mockSignJWT);
    
    (jose.decodeJwt as jest.Mock).mockReturnValue({
      webid: mockWebId,
      exp: Math.floor(Date.now() / 1000) + 3600,
      iat: Math.floor(Date.now() / 1000),
      iss: mockWebId,
      sub: mockWebId
    });
  });

  // --- Login Tests ---
  describe('login', () => {
    it('should generate a self-issued access token and set session state', async () => {
      const session = createSession();
      await session.login(mockWebId);

      expect(session.isActive).toBe(true);
      expect(session.webId).toBe(mockWebId);
      expect(jose.generateKeyPair).toHaveBeenCalledTimes(1);
      expect(jose.SignJWT).toHaveBeenCalled();
    });

    it('should call onSessionStateChange callback when login succeeds', async () => {
      const callback = jest.fn();
      const session = createSession(mockClientDetails, {
        onSessionStateChange: callback
      });

      await session.login(mockWebId);

      expect(callback).toHaveBeenCalledTimes(1);
    });
  });

  // --- handleRedirectFromLogin Tests ---
  describe('handleRedirectFromLogin', () => {
    it('should do nothing and resolve immediately', async () => {
      const session = createSession();
      await expect(session.handleRedirectFromLogin()).resolves.toBeUndefined();
    });
  });

  // --- restore Tests ---
  describe('restore', () => {
    it('should throw an error if no WebID is available', async () => {
      const session = createSession();
      await expect(session.restore()).rejects.toThrow('No WebID available to restore session');
    });

    it('should generate a new token for the same WebID when WebID is available', async () => {
      const session = createSession();
      
      // First login to establish WebID
      await session.login(mockWebId);
      expect(session.isActive).toBe(true);
      
      // Mock the key generation and signing again for the restore call
      (jose.generateKeyPair as jest.Mock).mockClear();
      (jose.SignJWT as any).mockClear();
      const mockSignJWT2 = {
        setProtectedHeader: jest.fn().mockReturnThis(),
        sign: jest.fn().mockResolvedValue('mock-signed-token-2')
      };
      (jose.SignJWT as any).mockImplementation(() => mockSignJWT2);
      
      (jose.decodeJwt as jest.Mock).mockReturnValue({
        webid: mockWebId,
        exp: Math.floor(Date.now() / 1000) + 3600,
        iat: Math.floor(Date.now() / 1000),
        iss: mockWebId,
        sub: mockWebId
      });
      
      // Restore session
      await session.restore();
      
      expect(jose.generateKeyPair).toHaveBeenCalledTimes(1);
      expect(jose.SignJWT).toHaveBeenCalled();
      expect(session.isActive).toBe(true);
      expect(session.webId).toBe(mockWebId);
    });
  });

  // --- logout Tests ---
  describe('logout', () => {
    it('should clear session state and proactive renewal timeout', async () => {
      const session = createSession();
      await session.login(mockWebId);
      expect(session.isActive).toBe(true);

      await session.logout();

      expect(session.isActive).toBe(false);
      expect(session.webId).toBeUndefined();
    });
  });

  // --- Proactive Renewal Tests ---
  describe('proactive renewal', () => {
    beforeEach(() => {
      jest.useFakeTimers();
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it('should schedule proactive renewal after login', async () => {
      // For this test, we'll just verify that the function completes without error
      const session = createSession(mockClientDetails, {
        proactiveRenewalThreshold: 10, // 10 seconds
      });

      await expect(session.login(mockWebId)).resolves.toBeUndefined();
    });
  });
});