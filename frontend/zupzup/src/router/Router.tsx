import { BrowserRouter, Route, Routes } from 'react-router-dom';

import * as pages from 'pages';
import * as utils from 'utils';
import { Layout } from 'components';

const Router = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path={utils.URL.MAIN.HOME} element={<Layout />}>
          <Route path="/" element={<pages.OnBoarding />} />
          <Route
            path={utils.URL.CALENDAR.CALENDAR}
            element={<pages.PloggingRecord />}
          />
          <Route
            path={utils.URL.PLOGGING.LOBBY}
            element={<pages.PloggingStart />}
          />
          <Route path={utils.URL.PLOGGING.CAMERA} element={<pages.Camera />} />
          <Route path={utils.URL.PLOGGING.ON} element={<pages.OnPlogging />} />
          <Route
            path={utils.URL.PLOGGING.TRASH}
            element={<pages.TrashReport />}
          />

          <Route path={utils.URL.LOGIN.HOME} element={<pages.Login />} />
          <Route
            path={utils.URL.PLOGGING.REPORT}
            element={<pages.PloggingReport />}
          />

          <Route
            path={utils.URL.LOGIN.REGIST_INFO + '/physical'}
            element={<pages.RegistInfoPhysical />}
          />
          <Route
            path={utils.URL.LOGIN.REGIST_INFO + '/profile'}
            element={<pages.RegistInfoProfile />}
          />

          <Route
            path={utils.URL.RESULT.REGIST}
            element={<pages.RegistSuccess />}
          />
          <Route
            path={utils.URL.RESULT.FLOGGING}
            element={<pages.PloggingDone />}
          />
          <Route path={utils.URL.LOADING} element={<pages.Loading />} />

          <Route path={utils.URL.MYPAGE.HOME} element={<pages.MyPage />} />
          <Route
            path={utils.URL.SETTING.HOME}
            element={<pages.SettingPage />}
          />
          <Route
            path={utils.URL.SETTING.PROFILE}
            element={<pages.ProfileSettingPage />}
          />
          <Route path="*" element={<pages.Error />}></Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default Router;
