import styled from 'styled-components';
import AngleLeftSvg from 'assets/icons/angle-left.svg?react';
import { useNavigate } from 'react-router-dom';
import BlankFrame from './BlankFrame';

interface Props {
  title?: string;
  rightComponent?: React.ReactElement;
}

const TopNavigation = (props: Props) => {
  const navigate = useNavigate();
  return (
    <>
      <BlankFrame margin={15} />
      <S.Wrap>
        <S.LeftSection onClick={() => navigate(-1)}>
          <AngleLeftSvg />
        </S.LeftSection>
        {props.title && <S.MiddleSection>{props.title}</S.MiddleSection>}
        {props.rightComponent && (
          <S.RightSection>{props.rightComponent}</S.RightSection>
        )}
      </S.Wrap>
    </>
  );
};

const S = {
  Wrap: styled.div`
    width: 100%;
    display: flex;
    align-items: center;
    height: 44px;
    justify-content: space-between;
  `,

  LeftSection: styled.div`
    cursor: pointer;
    display: flex;
    width: 40px;
    justify-content: center;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
  `,
  MiddleSection: styled.div`
    display: flex;
    align-items: center;
    text-align: center;
    flex-basis: 1;
    font-family: ${({ theme }) => theme.font.family.focus2};
    font-size: ${({ theme }) => theme.font.size.focus1};
    color: ${({ theme }) => theme.color.gray1};
  `,
  RightSection: styled.div`
    cursor: pointer;
    min-width: 40px;
  `,
};

export default TopNavigation;
