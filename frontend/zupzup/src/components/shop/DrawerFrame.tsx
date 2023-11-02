import { styled } from 'styled-components';
import { useNavigate } from 'react-router-dom';
import * as utils from 'utils';
import { Food } from 'types/Food';

export interface DrawerFrameProps {
  foodList: Food[];
}

export const DrawerFrame: React.FC<DrawerFrameProps> = ({ foodList }) => {
  const navigate = useNavigate();
  const handleClickOpen = (foodId: number) => {
    navigate(utils.URL.MYPAGE.SHOP_DETAIL + `/${foodId}`);
  };

  return (
    <S.Wrap>
      <S.RowFrame>
        {foodList.map((food, index) => (
          <S.FoodContainer key={index}>
            <S.FoodImage
              src={food.image}
              onClick={() => handleClickOpen(food.id)}
            />
          </S.FoodContainer>
        ))}
      </S.RowFrame>
      <S.Image src="assets/images/drawer.png"></S.Image>
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    width: 100%;
  `,

  RowFrame: styled.div`
    display: flex;
    justify-content: space-around;
    flex-wrap: wrap;
    width: 100%;
  `,

  FoodContainer: styled.div`
    display: flex;
    width: fit-content;
    align-items: center;
    justify-content: center;
    margin: 0 10px -30px;
    position: relative;
  `,

  FoodImage: styled.img`
    z-index: 999;
    width: 80px;
  `,

  Image: styled.img`
    width: 100%;
  `,
};
