import { Coin, DrawerCarousel, TopNavigation } from 'components';
import styled from 'styled-components';
import { URL } from 'utils';
import { Food } from 'types/Food';

const FoodList: Food[] = [
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/가리비.png',
  },
  {
    id: 2,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/새우.png',
  },
  {
    id: 3,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/홍합.png',
  },
  {
    id: 4,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/연어+스테이크.png',
  },
  {
    id: 5,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/오징어.png',
  },
  {
    id: 6,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/문어.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/꽃게.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/물고기.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/랍스타.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/햄버거.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/샐러드.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/초밥.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/베이컨.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/피자.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/치킨.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/크로와상.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/우유.png',
  },
  {
    id: 1,
    image:
      'https://zupzup-assets.s3.ap-northeast-2.amazonaws.com/food/소시지.png',
  },
];
const ShoppingList = () => {
  return (
    <S.Wrap>
      <TopNavigation
        rightComponent={<Coin coin={320} />}
        navigationTo={URL.MYPAGE.HOME}
      />
      <S.TitleFrame>
        <S.MainTitle>상점</S.MainTitle>
        <S.SubTitle>캐릭터의 성장을 위한 아이템을 구매해보세요!</S.SubTitle>
      </S.TitleFrame>
      <DrawerCarousel foodList={FoodList} />
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
};
export default ShoppingList;
