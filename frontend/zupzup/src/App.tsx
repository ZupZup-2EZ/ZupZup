import { ThemeProvider } from 'styled-components';

import * as styles from 'styles';
import * as router from 'router';

const App = () => {
  return (
    <ThemeProvider theme={styles.Theme}>
      <styles.GlobalStyles />
      <router.Router />
    </ThemeProvider>
  );
};

export default App;
