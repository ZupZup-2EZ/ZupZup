import { Loading } from 'pages';
import styled from 'styled-components';
import { useState, useEffect } from 'react';
import { TrashTable } from 'types/PloggingReport';
import { TrashApis } from 'api';
import { TrashDetail } from 'types';

interface Props {
  trashInfo: TrashDetail;
}
const PloggingMemo = ({ trashInfo }: Props) => {
  const [coinTable, setCoinTable] = useState<TrashTable>();

  useEffect(() => {
    async function load() {
      const coinData = await TrashApis.getTrashDetail();
      const coinTableFromJson = coinData.data;
      setCoinTable(coinTableFromJson);
    }
    load();
  }, []);
  return (
    <S.MemoFrame>
      {coinTable ? (
        Object.keys(trashInfo)
          .filter((type: string) => trashInfo[type] > 0)
          .map((type, idx) => (
            <li key={idx}>
              <div className="text">
                <div className="name">{coinTable[type].kor}</div>
                <div className="count">{trashInfo[type]}회</div>
              </div>
            </li>
          ))
      ) : (
        <Loading />
      )}
    </S.MemoFrame>
  );
};

const S = {
  Wrap: styled.div`
    display: flex;
    width: 100%;
    flex-direction: column;
    align-items: end;
    justify-content: center;
    font-family: ${({ theme }) => theme.font.family.body2};
  `,

  MemoFrame: styled.ul`
    list-style-position: inside;
    width: 92%;
    background: ${({ theme }) => theme.color.white};
    /* box-shadow: 0.15rem 0.15rem 0.5rem rgb(0 0 0 / 0.15); */
    padding: 0;
    margin: 0;
    border-radius: 4px;

    li {
      padding: 0 0 0 1.5rem;
      position: relative;
      height: 32px;
      display: flex;
      align-items: center;
      width: 100;
    }

    li:not(:last-child) {
      border-bottom: 1px solid ${({ theme }) => theme.color.sub2};
    }

    li:first-child {
      margin-top: 0.6rem;
    }

    li:last-child {
      margin-bottom: 0.6rem;
    }

    li::before {
      content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='14' viewBox='0 0 50 50'%3E%3Cpath d='M46.4 16.2c-2.3-2.3-5.4-3.5-8.4-4.5-.5-.2-1.1-.3-1.6-.5-1.6-1.6-3.7-2.8-6.2-3.2-1-.2-1.9.1-2.5.6-.9-.3-1.8-.6-2.7-.8-3.2-1-6.4-1.8-9.5-.1-1 .5-1.9 1.2-2.7 2-6.4 1.4-11.7 5-12.4 12.7C0 27 1.9 31.5 4.9 34.9c.1.6.2 1.1.4 1.7 1 3.2 3.3 5.7 6.7 6.5 2.7.6 5.4-.2 7.9-1.2 3.3.4 6.7.3 9.9 0 6.5-.7 13.3-2.8 17.1-8.5 3.6-5.2 4-12.6-.5-17.2zm-17.3.9c2.1.4 4 1.7 4.7 3.8 0 .5-.1 1.1-.2 1.6-.3 1.4-.8 2.6-1.6 3.7-.7.2-1.5.1-2.3-.4-.8-.4-1.6-1-2.2-1.6-.4-.4-1.2-1.7-1.6-1.9 3.4 1.3 5.1-3 3.2-5.2zm-11.6 9.7c.2-1.9 1.1-3.9 2.3-5.5-.4 2.1.3 4.2 1.7 6 1.3 1.7 3.1 3.2 5 4.2-.2.1-.4.2-.6.4-.1 0-.1.1-.2.1-3.9.2-8.7-.8-8.2-5.2zm-6.4 3.1c.1.3.1.7.2 1 .2.6.4 1.2.7 1.8-.4-.2-.7-.5-1-.7.1-.8.1-1.4.1-2.1zm31.2-1.3c-.9 1.7-2.1 3.1-3.7 4.1 2-2.1 3.4-4.7 4-7.6.2-.7.3-1.4.3-2.1.6 1.5.5 3.3-.6 5.6z'/%3E%3C/svg%3E")
        ' ';
      filter: ${({ theme }) => theme.color.darkFilter};
      margin-right: 10px;
    }

    li:nth-child(3n)::before {
      content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='14' viewBox='0 0 50 50'%3E%3Cpath d='M46.5 12.5c-.4-1.1-1.3-1.8-2.2-2-4.2-4-11.6-4.3-17.1-4.1-6.9.3-13.9 2.1-19.4 6.5C2 17.5-2.4 25.7 2.5 32.6c2.2 3.2 5.5 4.9 9 5.5 3.3 1.7 6.7 3.3 10.2 4.4 7.8 2.3 17 1.6 23.2-4.3 7.3-7 4.8-17.3 1.6-25.7zm-20.2 2.7c.6 0 1.3 0 1.8.2 1.1.4 1.7 1.3 2 2.3-1-1.2-2.4-2.1-3.8-2.5zm-1.4 6.6c.9.9 1.3 2.2-.2 2.3-2 .2-1.1-1.9.2-2.3zm-11.8 9.8c-.6-.3-2.9-1.1-3.2-1.8-.2-.5 1.4-3.1 2.1-4.2.3.5.7 1 1.2 1.4 0 .3.1.6.2.8.5 1.9 1.5 3.1 2.9 4h-.2c-.8.1-1.6.1-2.5-.1-.2 0-.3 0-.5-.1zM24 36.4c1.6-.7 3-1.5 4.3-2.5.8.2 1.7.3 2.5.5 2.5.4 5.2.9 7.7.6-.9.6-2 1.1-3 1.4-3.9 1.3-7.7 1-11.5 0z'/%3E%3C/svg%3E");
    }

    li:nth-child(3n - 1)::before {
      content: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' xml:space='preserve' width='14' viewBox='0 0 50 50'%3E%3Cpath d='M48.3 23.7c-1-9.9-9.9-15.6-18.8-17.8-8.2-2.1-18.8-2.6-24.6 4.8C.6 16.2 1 23.6 4.3 29.3c-.5 1-.8 2-1 3-.6 4 2 7.6 5.1 10 5.9 4.4 14 4.2 19.6-.4 1.5 0 2.9-.2 4.4-.5 1.8 0 3.5 0 5.3-.1 2.3-.1 3.5-1.9 3.5-3.7 4.5-3.3 7.7-8.2 7.1-13.9zM9.1 17.8c1.1-4.1 4.9-5.8 8.8-6.1.9-.1 1.9-.1 2.9-.1-3.2 1.6-6.3 4.6-8 7.4-.1.1-.1.2-.2.3-1.1.9-2.1 1.9-3 2.9-.2.2-.4.4-.5.6-.4-1.7-.5-3.3 0-5z'/%3E%3C/svg%3E");
    }

    & .text {
      display: flex;
      align-items: center;
      justify-content: space-between;
      width: 100%;
      padding-right: 1.5rem;

      & .count {
        font-family: ${({ theme }) => theme.font.family.focus2};
        font-size: ${({ theme }) => theme.font.size.body2};
      }
    }
  `,
};

export default PloggingMemo;
