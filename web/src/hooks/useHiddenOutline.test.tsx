import { renderHook, fireEvent } from 'test-utils';
import useHiddenOutline from './useHiddenOutline';

test('it adds a tab-related class when <Tab> is pressed and removes it on mouse click', () => {
  renderHook(() => useHiddenOutline());

  fireEvent.keyUp(document.body, { key: 'Tab' });
  expect(document.body).toHaveClass('user-is-tabbing');

  fireEvent.keyPress(document.body, { key: 'Enter' });
  expect(document.body).toHaveClass('user-is-tabbing');

  fireEvent.mouseUp(document.body);
  expect(document.body).not.toHaveClass('user-is-tabbing');
});
