import styled from 'styled-components';
import { useNavigate } from 'react-router-dom';

import * as utils from 'utils';

import CoinSvg from 'assets/icons/coin.svg?react';
import ShopSvg from 'assets/icons/shop.svg?react';
import SettingSvg from 'assets/icons/setting.svg?react';

interface Props {
  coin: number;
}

const MyPageNav = ({ coin }: Props) => {
  const navigate = useNavigate();
  return (
    <S.Wrap>
      <S.LeftSection>
        <CoinSvg />
        <span>{coin}</span>
      </S.LeftSection>
      <S.RightSection>
        <ShopSvg onClick={() => navigate(utils.URL.MYPAGE.SHOP)} />
        <SettingSvg onClick={() => navigate(utils.URL.SETTING.HOME)} />
      </S.RightSection>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    width: 100%;
    display: flex;
    align-items: center;
    height: 44px;
    justify-content: space-between;
    overflow: hidden;
  `,

  LeftSection: styled.div`
    cursor: pointer;
    display: flex;
    justify-content: center;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
    span {
      color: ${({ theme }) => theme.color.gray2};
      font-weight: ${({ theme }) => theme.font.weight.body2};
      font-size: ${({ theme }) => theme.font.size.body2};
      font-family: ${({ theme }) => theme.font.family.focus2};
      margin-top: 2px;
    }
  `,

  RightSection: styled.div`
    cursor: pointer;
    display: flex;
    gap: 8px;
  `,
};

export default MyPageNav;
