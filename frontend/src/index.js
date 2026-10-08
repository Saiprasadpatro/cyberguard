import React from 'react';
import ReactDOM from 'react-dom/client';
// Fonts are bundled with the app (no Google Fonts request), so the UI looks
// the same in offline mode.
import '@fontsource/ibm-plex-sans/400.css';
import '@fontsource/ibm-plex-sans/500.css';
import '@fontsource/ibm-plex-sans/600.css';
import '@fontsource/ibm-plex-sans/700.css';
import '@fontsource/ibm-plex-mono/400.css';
import '@fontsource/ibm-plex-mono/600.css';
import 'bootstrap/dist/css/bootstrap.min.css';
import './styles/theme.css';
import './styles/motion.css';
import App from './App';

const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
