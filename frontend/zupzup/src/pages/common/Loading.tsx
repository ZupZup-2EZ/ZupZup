import styled from 'styled-components';
import { LoadingAnimation } from 'components';

const Loading = () => {
  return (
    <S.Wrap>
      <LoadingAnimation />
    </S.Wrap>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    overflow: hidden;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
};
export default Loading;
