import { render, screen } from '@testing-library/react';
import App from './App';

jest.mock('./services/api', () => ({
  authAPI: {
    getProfile: jest.fn().mockRejectedValue(new Error('unauthorized')),
  },
}));

test('renders login page', async () => {
  render(<App />);
  expect(await screen.findByRole('button', { name: /sign in/i })).toBeInTheDocument();
  expect(screen.getByRole('heading', { name: /sign in to cryptodetect/i })).toBeInTheDocument();
});
