import styled from 'styled-components';

import { PloggingStartBackground, PloggingMap, Navigation } from 'components';

const PloggingStart = () => {
  return (
    <S.Wrap>
      <PloggingStartBackground />
      <PloggingMap />
      <Navigation />
    </S.Wrap>
  );
};

export default PloggingStart;

const S = {
  Wrap: styled.div`
    position: relative;
    display: flex;
    flex-direction: column;
    width: 100%;
    height: 100vh;
    background-color: ${({ theme }) => theme.color.background};
  `,
};
