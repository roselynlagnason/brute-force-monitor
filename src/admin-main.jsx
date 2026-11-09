import React from 'react';
import { createRoot } from 'react-dom/client';
import AdminApp from './AdminApp.jsx';
import './style.css';
import './theme.css';
import './admin.css';
import './noir.css';
createRoot(document.getElementById('root')).render(<React.StrictMode><AdminApp /></React.StrictMode>);
