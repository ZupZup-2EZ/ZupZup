import { Coin, ConfirmButton, FoodDetailPage, TopNavigation } from 'components';
import { useEffect } from 'react';
import { useNavigate, useParams } from 'react-router-dom';
import styled from 'styled-components';
import { FoodDetail } from 'types/Food';
import * as utils from 'utils';
import axios from 'api/apiController';

const FoodDetail: FoodDetail = {
  id: 2,
  image: `https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/소시지.png`,
  name: '햄버거',
  coin: 4,
  exp: 3,
};
const EachShopDetail = () => {
  const navigate = useNavigate();
  const { id } = useParams<{ id: string }>();

  useEffect(() => {
    axios.get(`/${id}`);
  }, [id]);

  return (
    <S.Wrap>
      <TopNavigation rightComponent={<Coin coin={320} />} />
      <S.TitleFrame>
        <S.MainTitle>상점</S.MainTitle>
        <S.SubTitle>캐릭터의 성장을 위한 아이템을 구매해보세요!</S.SubTitle>
      </S.TitleFrame>
      <S.Content>
        <FoodDetailPage foodDetail={FoodDetail} />
        <S.ButtonSection>
          <ConfirmButton
            text="다시 선택하기"
            color="#a0a0a0"
            onClick={() => navigate(utils.URL.MYPAGE.SHOP)}
          />
          <ConfirmButton
            text="구입하기"
            onClick={() => navigate(utils.URL.MYPAGE.PURCHASE)}
          />
        </S.ButtonSection>
      </S.Content>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    overflow: hidden;
    width: 100%;
    height: 100vh;
  `,

  TitleFrame: styled.div`
    margin: 24px 0 0 20px;
  `,
  MainTitle: styled.div`
    font-size: ${({ theme }) => theme.font.size.display1};
    font-family: ${({ theme }) => theme.font.family.display1};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.display1};
  `,
  SubTitle: styled.div`
    margin-top: 6px;
    color: ${({ theme }) => theme.color.gray2};
    font-size: ${({ theme }) => theme.font.size.body2};
    font-family: ${({ theme }) => theme.font.family.body2};
    font-weight: ${({ theme }) => theme.font.weight.body2};
    line-height: ${({ theme }) => theme.font.lineheight.body2};
  `,

  Content: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    margin-top: 50px;
    height: 100%;
  `,

  ButtonSection: styled.div`
    margin: auto 0 50px 0;
    display: flex;
    flex-direction: column;
    width: 100%;
    gap: 12px;
    & div {
      margin: 0 auto;
    }
  `,
};

export default EachShopDetail;
