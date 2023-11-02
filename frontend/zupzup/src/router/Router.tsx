import { BrowserRouter, Route, Routes } from 'react-router-dom';

import * as pages from 'pages';
import * as utils from 'utils';
import { Layout } from 'components';

const Router = () => {
  return (
    <BrowserRouter>
      <Routes>
        <Route path={utils.URL.MAIN.HOME} element={<Layout />}>
          <Route path="/" element={<pages.LoginOnboard />} />
          <Route
            path={utils.URL.CALENDAR.CALENDAR}
            element={<pages.PloggingRecord />}
          />
          <Route
            path={utils.URL.PLOGGING.LOBBY}
            element={<pages.PloggingStart />}
          />
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
            path={utils.URL.LOGIN.SUCCESS}
            element={<pages.LoginSuccess />}
          />

          <Route
            path={utils.URL.LOGIN.REGIST_INFO.PHYSICAL}
            element={<pages.RegistInfoPhysical />}
          />
          <Route
            path={utils.URL.LOGIN.REGIST_INFO.PROFILE}
            element={<pages.RegistInfoProfile />}
          />

          <Route
            path={utils.URL.RESULT.REGIST}
            element={<pages.RegistSuccess />}
          />

          <Route path={utils.URL.LOADING} element={<pages.Loading />} />

          <Route path={utils.URL.MYPAGE.HOME} element={<pages.MyPage />} />
          <Route
            path={utils.URL.MYPAGE.REPORT}
            element={<pages.MyPloggingReport />}
          />

          <Route
            path={utils.URL.MYPAGE.SHOP}
            element={<pages.ShoppingList />}
          />
          <Route
            path={utils.URL.MYPAGE.SHOP_DETAIL + '/:id'}
            element={<pages.EachShopDetail />}
          />
          <Route
            path={utils.URL.MYPAGE.PURCHASE}
            element={<pages.PurchaseSuccess />}
          />

          <Route
            path={utils.URL.SETTING.HOME}
            element={<pages.SettingPage />}
          />
          <Route
            path={utils.URL.SETTING.PROFILE}
            element={<pages.ProfileSettingPage />}
          />
          <Route path={utils.URL.SETTING.THEME} element={<pages.Theme />} />

          <Route path={utils.URL.OPINION} element={<pages.Opinion />} />
          <Route
            path={utils.URL.RESULT.OPINION}
            element={<pages.OpinionSuccess />}
          />

          <Route
            path={utils.URL.ONBORDING.CHARACTER}
            element={<pages.CharacterInfo />}
          />
          <Route
            path={utils.URL.ONBORDING.EXPLAIN}
            element={<pages.OnBoarding />}
          />

          <Route
            path={utils.URL.ONBORDING.WORKING}
            element={<pages.Working />}
          ></Route>
          <Route path="*" element={<pages.Error />}></Route>
        </Route>
      </Routes>
    </BrowserRouter>
  );
};

export default Router;
