import { Outlet } from 'react-router-dom';
import styled from 'styled-components';

import * as utils from 'utils';

const Layout = () => {
  return (
    <S.Wrap>
      <S.Main>
        <Outlet />
      </S.Main>
    </S.Wrap>
  );
};

export default Layout;

const S = {
  Wrap: styled.div`
    width: 100%;
    height: 100%;
    display: flex;
    justify-content: center;
    align-items: center;
  `,
  Main: styled.div`
    width: ${({ theme }) => theme.deviceSize.mobile360};
    min-height: 100vh;
    min-height: -webkit-fill-available;
    background-color: ${({ theme }) => theme.color.background};

    @media (max-width: ${utils.MAX_WIDTH}) {
      width: 100%;
      height: 100%;
    }
  `,
};
