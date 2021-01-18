import React from 'react';

const useHiddenOutline = () => {
  React.useEffect(() => {
    const handleTab = (e: KeyboardEvent) => {
      if (e.key === 'Tab' && !document.body.classList.contains('user-is-tabbing')) {
        // On tab, add a classname
        document.body.classList.add('user-is-tabbing');

        // and register a listener for 1 mouse click. When it happens, remove this classname
        const handleFirstClick = () => {
          document.body.classList.remove('user-is-tabbing');
          window.removeEventListener('mouseup', handleFirstClick, false);
        };
        window.addEventListener('mouseup', handleFirstClick, false);
      }
    };

    // Register a listener for tabs
    window.addEventListener('keyup', handleTab);
    return () => {
      window.removeEventListener('keyup', handleTab);
    };
  }, []);
};

export default useHiddenOutline;
